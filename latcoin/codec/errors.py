class CodecError(Exception):
    pass

class UnexpectedEOF(CodecError):
    pass

class NonCanonicalEncoding(CodecError):
    pass

class InvalidField(CodecError):
    pass
