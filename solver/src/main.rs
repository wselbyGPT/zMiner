use equihash::{is_valid_solution, solve_200_9};
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

const DUMMY_SOLUTION_SIZE: usize = 1344;
const POW_INPUT_SIZE: usize = 108;
const NONCE_SIZE: usize = 32;

#[derive(Debug, Deserialize)]
struct SolverRequest {
    mode: String,
    #[serde(default)]
    template: Option<TemplateSummary>,
    #[serde(default)]
    pow_input_hex: Option<String>,
    #[serde(default)]
    target_hex: Option<String>,
    #[serde(default)]
    max_nonces: Option<u64>,
    #[serde(default)]
    max_solutions: Option<u64>,
    #[serde(default)]
    require_target: Option<bool>,
    #[serde(default)]
    start_nonce_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TemplateSummary {
    height: Option<u64>,
    version: Option<i64>,
    previousblockhash: Option<String>,
    bits: Option<String>,
    curtime: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
struct SolverCandidate {
    nonce32_hex: String,
    solution_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pow_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_met: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SolverResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce32_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pow_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checked_nonces: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_met: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidates: Option<Vec<SolverCandidate>>,
}

fn main() {
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        emit_error(format!("failed to read stdin: {err}"));
        return;
    }

    let req: SolverRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(err) => {
            emit_error(format!("invalid JSON request: {err}"));
            return;
        }
    };

    if let Some(template) = &req.template {
        let _template_hint = (
            template.height,
            template.version,
            template.previousblockhash.as_deref(),
            template.bits.as_deref(),
            template.curtime,
        );
    }

    match req.mode.as_str() {
        "none" => emit(SolverResponse {
            status: "no_solution".into(),
            message: Some("solver in 'none' mode".into()),
            nonce32_hex: None,
            solution_hex: None,
            pow_hash_hex: None,
            checked_nonces: Some(0),
            target_met: None,
            candidates: None,
        }),
        "dummy" => {
            let nonce = vec![0u8; NONCE_SIZE];
            let solution = vec![0u8; DUMMY_SOLUTION_SIZE];
            emit(SolverResponse {
                status: "ok".into(),
                message: Some(
                    "dummy control-plane solution only; not valid on real PoW networks".into(),
                ),
                nonce32_hex: Some(hex_encode(&nonce)),
                solution_hex: Some(hex_encode(&solution)),
                pow_hash_hex: None,
                checked_nonces: Some(1),
                target_met: Some(false),
                candidates: None,
            })
        }
        "real" => emit(solve_real(&req)),
        "real_batch" => emit(solve_real_batch(&req)),
        other => emit_error(format!("unsupported solver mode: {other}")),
    }
}

fn solve_real(req: &SolverRequest) -> SolverResponse {
    let pow_input = match parse_fixed_hex(req.pow_input_hex.as_deref(), POW_INPUT_SIZE, "pow_input_hex") {
        Ok(v) => v,
        Err(message) => return error_response(message),
    };
    let target = match parse_fixed_hex(req.target_hex.as_deref(), 32, "target_hex") {
        Ok(v) => v,
        Err(message) => return error_response(message),
    };
    let require_target = req.require_target.unwrap_or(true);
    let max_nonces = req.max_nonces.unwrap_or(16);
    let mut nonce = match parse_nonce(req.start_nonce_hex.as_deref()) {
        Ok(v) => v,
        Err(message) => return error_response(message),
    };

    for checked in 0..max_nonces {
        let this_nonce = nonce;
        let mut emitted = false;
        let solutions = solve_200_9(&pow_input, || {
            if emitted {
                None
            } else {
                emitted = true;
                Some(this_nonce)
            }
        });

        for solution in solutions {
            if is_valid_solution(200, 9, &pow_input, &this_nonce, &solution).is_err() {
                continue;
            }

            let header = build_header(&pow_input, &this_nonce, &solution);
            let pow_hash = sha256d(&header);
            let meets_target = hash_meets_target(&pow_hash, &target);

            if !require_target || meets_target {
                let mut pow_hash_rpc = pow_hash;
                pow_hash_rpc.reverse();
                return SolverResponse {
                    status: "ok".into(),
                    message: Some(if require_target {
                        "found valid Equihash solution meeting target".into()
                    } else {
                        "found valid Equihash solution".into()
                    }),
                    nonce32_hex: Some(hex_encode(this_nonce)),
                    solution_hex: Some(hex_encode(solution)),
                    pow_hash_hex: Some(hex_encode(pow_hash_rpc)),
                    checked_nonces: Some(checked + 1),
                    target_met: Some(meets_target),
                    candidates: None,
                };
            }
        }

        if !increment_nonce_le(&mut nonce) {
            return SolverResponse {
                status: "no_solution".into(),
                message: Some("nonce space exhausted".into()),
                nonce32_hex: None,
                solution_hex: None,
                pow_hash_hex: None,
                checked_nonces: Some(checked + 1),
                target_met: None,
                candidates: None,
            };
        }
    }

    SolverResponse {
        status: "no_solution".into(),
        message: Some("no valid Equihash solution found in requested nonce window".into()),
        nonce32_hex: None,
        solution_hex: None,
        pow_hash_hex: None,
        checked_nonces: Some(max_nonces),
        target_met: None,
        candidates: None,
    }
}

fn solve_real_batch(req: &SolverRequest) -> SolverResponse {
    let pow_input = match parse_fixed_hex(req.pow_input_hex.as_deref(), POW_INPUT_SIZE, "pow_input_hex") {
        Ok(v) => v,
        Err(message) => return error_response(message),
    };
    let target = match parse_fixed_hex(req.target_hex.as_deref(), 32, "target_hex") {
        Ok(v) => v,
        Err(message) => return error_response(message),
    };
    let require_target = req.require_target.unwrap_or(false);
    let max_nonces = req.max_nonces.unwrap_or(64);
    let max_solutions = req.max_solutions.unwrap_or(8);
    let mut nonce = match parse_nonce(req.start_nonce_hex.as_deref()) {
        Ok(v) => v,
        Err(message) => return error_response(message),
    };

    let mut candidates: Vec<SolverCandidate> = Vec::new();

    for checked in 0..max_nonces {
        let this_nonce = nonce;
        let mut emitted = false;
        let solutions = solve_200_9(&pow_input, || {
            if emitted {
                None
            } else {
                emitted = true;
                Some(this_nonce)
            }
        });

        for solution in solutions {
            if is_valid_solution(200, 9, &pow_input, &this_nonce, &solution).is_err() {
                continue;
            }

            let header = build_header(&pow_input, &this_nonce, &solution);
            let pow_hash = sha256d(&header);
            let meets_target = hash_meets_target(&pow_hash, &target);

            if require_target && !meets_target {
                continue;
            }

            let mut pow_hash_rpc = pow_hash;
            pow_hash_rpc.reverse();
            candidates.push(SolverCandidate {
                nonce32_hex: hex_encode(this_nonce),
                solution_hex: hex_encode(solution),
                pow_hash_hex: Some(hex_encode(pow_hash_rpc)),
                target_met: Some(meets_target),
            });

            if candidates.len() as u64 >= max_solutions {
                return SolverResponse {
                    status: "ok".into(),
                    message: Some("collected batch of valid Equihash solutions".into()),
                    nonce32_hex: None,
                    solution_hex: None,
                    pow_hash_hex: None,
                    checked_nonces: Some(checked + 1),
                    target_met: None,
                    candidates: Some(candidates),
                };
            }
        }

        if !increment_nonce_le(&mut nonce) {
            return if candidates.is_empty() {
                SolverResponse {
                    status: "no_solution".into(),
                    message: Some("nonce space exhausted".into()),
                    nonce32_hex: None,
                    solution_hex: None,
                    pow_hash_hex: None,
                    checked_nonces: Some(checked + 1),
                    target_met: None,
                    candidates: None,
                }
            } else {
                SolverResponse {
                    status: "ok".into(),
                    message: Some("nonce space exhausted after collecting some valid Equihash solutions".into()),
                    nonce32_hex: None,
                    solution_hex: None,
                    pow_hash_hex: None,
                    checked_nonces: Some(checked + 1),
                    target_met: None,
                    candidates: Some(candidates),
                }
            };
        }
    }

    if candidates.is_empty() {
        SolverResponse {
            status: "no_solution".into(),
            message: Some("no valid Equihash solutions found in requested nonce window".into()),
            nonce32_hex: None,
            solution_hex: None,
            pow_hash_hex: None,
            checked_nonces: Some(max_nonces),
            target_met: None,
            candidates: None,
        }
    } else {
        SolverResponse {
            status: "ok".into(),
            message: Some("collected valid Equihash solutions in requested nonce window".into()),
            nonce32_hex: None,
            solution_hex: None,
            pow_hash_hex: None,
            checked_nonces: Some(max_nonces),
            target_met: None,
            candidates: Some(candidates),
        }
    }
}

fn build_header(pow_input: &[u8], nonce: &[u8; NONCE_SIZE], solution: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pow_input.len() + NONCE_SIZE + 3 + solution.len());
    out.extend_from_slice(pow_input);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&compact_size(solution.len() as u64));
    out.extend_from_slice(solution);
    out
}

fn compact_size(n: u64) -> Vec<u8> {
    if n < 253 {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut out = vec![0xfd];
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out
    } else if n <= 0xFFFF_FFFF {
        let mut out = vec![0xfe];
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out
    } else {
        let mut out = vec![0xff];
        out.extend_from_slice(&n.to_le_bytes());
        out
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn hash_meets_target(pow_hash: &[u8; 32], target_be: &[u8]) -> bool {
    let mut pow_hash_be = *pow_hash;
    pow_hash_be.reverse();
    pow_hash_be.as_slice() <= target_be
}

fn parse_fixed_hex(value: Option<&str>, expected_len: usize, name: &str) -> Result<Vec<u8>, String> {
    let value = value.ok_or_else(|| format!("missing required field: {name}"))?;
    let decoded = hex_decode(value).map_err(|err| format!("invalid hex for {name}: {err}"))?;
    if decoded.len() != expected_len {
        return Err(format!(
            "{name} must decode to {expected_len} bytes, got {}",
            decoded.len()
        ));
    }
    Ok(decoded)
}

fn parse_nonce(value: Option<&str>) -> Result<[u8; NONCE_SIZE], String> {
    if let Some(value) = value {
        let decoded = parse_fixed_hex(Some(value), NONCE_SIZE, "start_nonce_hex")?;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&decoded);
        Ok(nonce)
    } else {
        Ok([0u8; NONCE_SIZE])
    }
}

fn increment_nonce_le(nonce: &mut [u8; NONCE_SIZE]) -> bool {
    for b in nonce.iter_mut() {
        let (new_value, overflowed) = b.overflowing_add(1);
        *b = new_value;
        if !overflowed {
            return true;
        }
    }
    false
}

fn emit(resp: SolverResponse) {
    println!("{}", serde_json::to_string(&resp).unwrap());
}

fn emit_error(message: String) {
    emit(error_response(message));
}

fn error_response(message: String) -> SolverResponse {
    SolverResponse {
        status: "error".into(),
        message: Some(message),
        nonce32_hex: None,
        solution_hex: None,
        pow_hash_hex: None,
        checked_nonces: None,
        target_met: None,
        candidates: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{compact_size, hash_meets_target, increment_nonce_le};

    #[test]
    fn compact_size_1344_matches_zcash_header_encoding() {
        assert_eq!(compact_size(1344), vec![0xfd, 0x40, 0x05]);
    }

    #[test]
    fn little_endian_nonce_increment_rolls_over_correctly() {
        let mut nonce = [0u8; 32];
        assert!(increment_nonce_le(&mut nonce));
        assert_eq!(nonce[0], 1);

        let mut nonce = [0xffu8; 32];
        assert!(!increment_nonce_le(&mut nonce));
        assert_eq!(nonce, [0u8; 32]);
    }

    #[test]
    fn target_comparison_uses_reversed_hash_bytes() {
        let pow_hash = [0u8; 32];
        let target = [0u8; 32];
        assert!(hash_meets_target(&pow_hash, &target));

        let pow_hash = [0xffu8; 32];
        let target = [0u8; 32];
        assert!(!hash_meets_target(&pow_hash, &target));
    }
}
