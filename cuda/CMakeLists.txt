cmake_minimum_required(VERSION 3.24)
project(zk_cuda_worker LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

add_executable(zk_cuda_worker src/main.cu)
set_target_properties(zk_cuda_worker PROPERTIES
  CUDA_SEPARABLE_COMPILATION ON
  CUDA_ARCHITECTURES native
)
