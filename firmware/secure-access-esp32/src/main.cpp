#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>

// Definições dos novos pinos (Lado Único da Protoboard)
#define SCK_PIN  12
#define MISO_PIN 13
#define MOSI_PIN 11
#define SS_PIN   10
#define RST_PIN  14

MFRC522 mfrc522(SS_PIN, RST_PIN);

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    delay(10); // Aguarda a abertura da porta serial nativa
  }
  delay(1000); // Garante que o monitor do VS Code estabilize
  Serial.println("\n--- Conexao Serial Estabelecida! ---");

  // Inicializa o SPI nos pinos escolhidos para o S3
  SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
  
  mfrc522.PCD_Init();
  
  Serial.println("\n--- Teste de Hardware ESP32-S3 + RC522 ---");
  
  // Teste de comunicação com o chip
  byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
  Serial.print("Versao do MFRC522: 0x");
  Serial.println(v, HEX);

  if (v == 0x00 || v == 0xFF) {
    Serial.println("ERRO: Sensor nao detectado! Verifique as conexoes no lado da protoboard.");
  } else {
    Serial.println("Sensor detectado com sucesso! Aproxime uma tag...");
  }
}

void loop() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.print("UID da Tag:");
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();
  
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}