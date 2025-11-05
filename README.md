#include <LiquidCrystal.h>

// 1. Inclusão de Bibliotecas
#include <Wire.h>             // Necessário para a comunicação I2C
#include <LiquidCrystal_I2C.h> // Para o Display LCD 16x2 I2C
#include <Servo.h>            // Para o Micro Servo Motor 9g

// 2. Definição de Parâmetros e Pinos

// --- Configuração do LCD I2C ---
// O endereço I2C mais comum é 0x27 ou 0x3F.
// Se não funcionar, use o código I2C Scanner (disponível na web) para descobrir o seu.
const int ENDERECO_I2C = 0x27; 
const int COLS = 16;
const int ROWS = 2;
LiquidCrystal_I2C lcd(ENDERECO_I2C, COLS, ROWS);

// --- Pinos do Sensor Ultrassônico HC-SR04 ---
const int pinoTrig = 9;  // Pino Trigger (Saída)
const int pinoEcho = 10; // Pino Echo (Entrada)

// --- Pino do Servo Motor ---
const int pinoServo = 6; 
Servo meuServo; // Cria o objeto Servo

// 3. Variáveis Globais
long duracao;     // Armazena a duração do pulso (tempo de ida e volta do som)
int distancia_cm; // Armazena a distância calculada em centímetros
int angulo = 15;  // Posição inicial do servo motor

// ====================================================================
// 4. Função de Setup (Configuração Inicial)
// ====================================================================
void setup() {
  // Configuração do Servo Motor
  meuServo.attach(pinoServo); // Anexa o servo motor ao pino definido
  meuServo.write(angulo);    // Move o servo para a posição inicial
  
  // Configuração dos Pinos do HC-SR04
  pinMode(pinoTrig, OUTPUT); // Pino Trig como Saída
  pinMode(pinoEcho, INPUT);  // Pino Echo como Entrada
  
  // Configuração do Display LCD I2C
  lcd.init();      // Inicializa o LCD
  lcd.backlight(); // Liga a luz de fundo (backlight)
  lcd.print("Iniciando Scanner");
  lcd.setCursor(0, 1);
  lcd.print("AGUARDE...");
  delay(2000);
  lcd.clear();
}

// ====================================================================
// 5. Função para Medir a Distância (HC-SR04)
// ====================================================================
int medirDistancia() {
  // 1. Limpa o pino Trig (Garante que esteja em LOW)
  digitalWrite(pinoTrig, LOW);
  delayMicroseconds(2);

  // 2. Envia um pulso de 10us no Trig
  digitalWrite(pinoTrig, HIGH);
  delayMicroseconds(10);
  digitalWrite(pinoTrig, LOW);

  // 3. Lê o pulso do Echo - retorna o tempo de duração em microsegundos
  duracao = pulseIn(pinoEcho, HIGH);

  // 4. Cálculo da Distância (em cm)
  // Distância = (Tempo * Velocidade do Som) / 2
  // Distância = duracao / 58.8
  distancia_cm = duracao / 58; // Usando 58 para maior precisão comum

  // Limita a distância máxima (opcional, para evitar lixo)
  if (distancia_cm > 400 || distancia_cm < 0) {
    return 400; // Retorna 400cm para indicar "fora de alcance"
  } else {
    return distancia_cm;
  }
}

// ====================================================================
// 6. Função de Loop (Execução Contínua)
// ====================================================================
void loop() {
  // --- Varredura para a Direita (de 15° a 165°) ---
  for (angulo = 15; angulo <= 165; angulo += 10) {
    meuServo.write(angulo); // Move o servo
    delay(100);             // Pausa para estabilização

    distancia_cm = medirDistancia(); // Realiza a medição

    // Exibe no LCD (Linha 0: Ângulo)
    lcd.setCursor(0, 0); 
    lcd.print("Angulo: ");
    lcd.print(angulo);
    lcd.print(" graus "); // Espaços para limpar a linha

    // Exibe no LCD (Linha 1: Distância)
    lcd.setCursor(0, 1); 
    lcd.print("Dist: ");
    lcd.print(distancia_cm);
    lcd.print(" cm       "); // Espaços para limpar a linha
  }

  // --- Varredura para a Esquerda (de 165° a 15°) ---
  for (angulo = 165; angulo >= 15; angulo -= 10) {
    meuServo.write(angulo); // Move o servo
    delay(100);             // Pausa para estabilização

    distancia_cm = medirDistancia(); // Realiza a medição

    // Exibe no LCD (Repetindo a exibição)
    lcd.setCursor(0, 0); 
    lcd.print("Angulo: ");
    lcd.print(angulo);
    lcd.print(" graus "); 

    lcd.setCursor(0, 1); 
    lcd.print("Dist: ");
    lcd.print(distancia_cm);
    lcd.print(" cm       "); 
  }
}
