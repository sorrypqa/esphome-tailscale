# Wrapper CMakeLists for microlink ESP-IDF component
# Builds microlink without driver/esp_driver_tsens dependencies
# Cellular and HTTP config server are disabled via Kconfig (not defined)

set(ML_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/../../microlink/components/microlink/src")
set(ML_INC_DIR "${CMAKE_CURRENT_LIST_DIR}/../../microlink/components/microlink/include")

set(SRCS
    "${ML_SRC_DIR}/microlink.c"
    "${ML_SRC_DIR}/ml_coord.c"
    "${ML_SRC_DIR}/ml_derp.c"
    "${ML_SRC_DIR}/ml_net_io.c"
    "${ML_SRC_DIR}/ml_wg_mgr.c"
    "${ML_SRC_DIR}/ml_stun.c"
    "${ML_SRC_DIR}/ml_noise.c"
    "${ML_SRC_DIR}/ml_h2.c"
    "${ML_SRC_DIR}/ml_udp.c"
    "${ML_SRC_DIR}/ml_tcp.c"
    "${ML_SRC_DIR}/ml_peer_nvs.c"
    "${ML_SRC_DIR}/nacl_box.c"
    "${ML_SRC_DIR}/ml_zerocopy.c"
    "${ML_SRC_DIR}/ml_config_httpd.c"
)

idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS
        "${ML_INC_DIR}"
        "${ML_SRC_DIR}"
    REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_timer
        lwip
        mbedtls
        json
    PRIV_REQUIRES
        wireguard_lwip
)
