"""PlatformIO pre-build script to add microlink ESP-IDF components."""
import os

Import("env")

# PROJECT_DIR is the ESPHome build dir (.esphome/build/esp32-tailscale)
# Walk up to find the actual project root (where microlink/ lives)
project_dir = env.subst("$PROJECT_DIR")

# The project root is 3 levels up from .esphome/build/esp32-tailscale
project_root = os.path.abspath(os.path.join(project_dir, "..", "..", ".."))
idf_components = os.path.join(project_root, "idf_components").replace("\\", "/")

cmake_file = os.path.join(project_dir, "CMakeLists.txt")
print(f"*** patch_cmake: root={project_root} cmake={cmake_file} exists={os.path.exists(cmake_file)}")

if os.path.exists(cmake_file):
    content = open(cmake_file).read()
else:
    # Generate the standard ESPHome CMakeLists.txt with our patch
    content = 'cmake_minimum_required(VERSION 3.16.0)\ninclude($ENV{IDF_PATH}/tools/cmake/project.cmake)\nproject(esp32-tailscale)\n'

if idf_components not in content:
    patched = content.replace(
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake)",
        'set(EXTRA_COMPONENT_DIRS "${EXTRA_COMPONENT_DIRS}" "' + idf_components + '")\n'
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake)",
    )
    open(cmake_file, "w").write(patched)
    print("*** Patched CMakeLists.txt with microlink EXTRA_COMPONENT_DIRS ***")
else:
    print("*** CMakeLists.txt already patched ***")
