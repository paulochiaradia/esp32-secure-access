#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include <mbedtls/md.h>
#include "time.h"

// --- CONFIGURAÇÕES DE REDE E SEGURANÇA ---
const char* ssid = "88888";
const char* password = "0000000";
const char* serverUrl = "aaaaaa";
const char* secretKey = "asasasasa+/P9Z+01X1w=";

// --- PINOS RC522 (CONEXÃO ESP32-S3) ---
#define SCK_PIN  12
#define MISO_PIN 13
#define MOSI_PIN 11
#define SS_PIN   10
#define RST_PIN  14

MFRC522 mfrc522(SS_PIN, RST_PIN);

// Função para gerar HMAC-SHA256 em Hexadecimal (Exatamente como o CyberChef faz)
String hmacSha256Hex(const String& key, const String& message) {
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mdInfo, 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)message.c_str(), message.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    char hexStr[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&hexStr[i * 2], "%02x", hmacResult[i]);
    }
    hexStr[64] = 0;
    return String(hexStr);
}

// Gera uma string aleatória única (Nonce)
String generateNonce() {
    String chars = "abcdef0123456789";
    String nonce = "";
    for (int i = 0; i < 8; i++) {
        nonce += chars[esp_random() % chars.length()];
    }
    return nonce;
}

// Obtém o timestamp Unix atual via NTP
unsigned long getTimestamp() {
    time_t now;
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo)) return 0;
    time(&now);
    return (unsigned long)now;
}

void setup() {
    Serial.begin(115200);
    
    // 1. Conexão Wi-Fi
    WiFi.begin(ssid, password);
    Serial.print("Conectando ao Wi-Fi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\n✅ WiFi Conectado!");

    // 2. Sincronização de Tempo (Crucial para o HMAC bater com o Backend)
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    Serial.print("Sincronizando relógio (NTP)");
    while (getTimestamp() < 1000000) { 
        delay(500);
        Serial.print(".");
    }
    Serial.println("\n✅ Tempo Sincronizado!");

    // 3. Inicialização do Hardware RFID
    SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
    mfrc522.PCD_Init();
    Serial.println("🚀 Sistema Ativo. Aproxime uma Tag autorizada...");
}

void loop() {
    // Verifica se há uma nova tag no sensor
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
        return;
    }

    Serial.println("\n--- Nova Leitura Detectada ---");

    // 1. Extrair UID e formatar para o Backend (Sem espaços, Maiúsculo)
    String uid = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        uid += (mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
        uid += String(mfrc522.uid.uidByte[i], HEX);
    }
    uid.toUpperCase();
    Serial.println("🎴 UID: " + uid);

    // 2. Gerar dados de segurança
    unsigned long ts = getTimestamp();
    String nonce = generateNonce();
    
    // IMPORTANTE: A ordem deve ser EXATAMENTE uid:timestamp:nonce
    String baseString = uid + ":" + String(ts) + ":" + nonce;
    String signature = hmacSha256Hex(secretKey, baseString);

    // 3. Montar o JSON
    JsonDocument doc;
    doc["uid"] = uid;
    doc["timestamp"] = ts;
    doc["nonce"] = nonce;
    doc["signature"] = signature;

    String jsonPayload;
    serializeJson(doc, jsonPayload);

    // 4. Enviar para a API em Go
    if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(serverUrl);
        http.addHeader("Content-Type", "application/json");

        Serial.println("📡 Enviando requisição segura...");
        int httpCode = http.POST(jsonPayload);

        if (httpCode > 0) {
            String response = http.getString();
            JsonDocument resDoc;
            deserializeJson(resDoc, response);

            if (httpCode == 200) {
                const char* user = resDoc["user"];
                Serial.printf("✅ [200] ACESSO LIBERADO! Bem-vindo, %s\n", user);
            } else if (httpCode == 403) {
                Serial.println("❌ [403] ACESSO NEGADO: Usuário não cadastrado.");
            } else if (httpCode == 401) {
                Serial.println("⚠️ [401] ERRO DE SEGURANÇA: Assinatura inválida.");
            } else {
                Serial.printf("❓ [%d] Resposta inesperada: %s\n", httpCode, response.c_str());
            }
        } else {
            Serial.printf("❌ Falha na conexão HTTP: %s\n", http.errorToString(httpCode).c_str());
        }
        http.end();
    }

    // Finalizar leitura e aguardar para evitar leituras duplicadas
    mfrc522.PICC_HaltA();
    delay(3000); 
}