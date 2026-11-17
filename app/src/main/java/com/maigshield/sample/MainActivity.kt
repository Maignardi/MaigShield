package com.maigshield.sample

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maigshield.sample.ui.theme.MaigShieldTheme
import com.maigshield.sdk.MaigShield
import com.maigshield.sdk.internal.crypto.DecryptedProofDiagnostic
import com.maigshield.sdk.internal.honeypot.DebugSecurityOverride
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            MaigShieldTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    BankDashboardScreen(
                        modifier = Modifier.padding(innerPadding),
                        onHoneypotTriggered = {
                            DebugSecurityOverride.disableSslPinning()
                            Toast.makeText(
                                this,
                                "Honeypot acionado! A flag FLAG_HONEYPOT_TRIGGERED foi gravada.",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    )
                }
            }
        }
    }
}

data class DiagnosticState(
    val proofToken: String,
    val diagnostic: DecryptedProofDiagnostic,
    val unscrambledFlags: Long
)

@Composable
fun BankDashboardScreen(
    modifier: Modifier = Modifier,
    onHoneypotTriggered: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var pixKey by remember { mutableStateOf("financeiro@empresa.com.br") }
    var amount by remember { mutableStateOf("1500.00") }
    var isProcessing by remember { mutableStateOf(false) }
    var diagnosticState by remember { mutableStateOf<DiagnosticState?>(null) }

    fun processPixTransfer() {
        scope.launch {
            isProcessing = true
            withContext(Dispatchers.IO) {
                val jsonPayload = """{"pixKey":"$pixKey","amount":$amount}"""
                val maigShield = MaigShield.getInstance()

                // Mint Zero-Boolean proof token bound to endpoint and body
                val token = maigShield.mintProofToken(
                    httpMethod = "POST",
                    urlPath = "/api/v1/pix/transfer",
                    requestBody = jsonPayload.toByteArray(Charsets.UTF_8)
                )

                // Decrypt locally using mock server private key for diagnostics
                val testPrivKey = SampleBankApp.sTestPrivateKey
                if (testPrivKey != null) {
                    val diag = maigShield.decryptDiagnosticProof(token, testPrivKey)
                    val rawFlags = maigShield.unscrambleDiagnosticFlags(
                        diag.scrambledFlags,
                        diag.salt,
                        diag.timestampNs
                    )
                    diagnosticState = DiagnosticState(token, diag, rawFlags)
                }
            }
            isProcessing = false
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text(
                text = "🛡️ MaigShield Tier-1 Defense",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Zero-Boolean RASP + Anti-Trojan + Biometria NDK + StrongBox",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Pix Transfer Simulation Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "💸 Simulação de Transferência Pix",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = pixKey,
                        onValueChange = { pixKey = it },
                        label = { Text("Chave Pix de Destino") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = amount,
                        onValueChange = { amount = it },
                        label = { Text("Valor (R$)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = { processPixTransfer() },
                        enabled = !isProcessing,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isProcessing) {
                            CircularProgressIndicator(
                                modifier = Modifier
                                    .height(20.dp)
                                    .width(20.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Assinando Envelope Criptográfico...")
                        } else {
                            Text("Confirmar Transferência Pix")
                        }
                    }
                }
            }
        }

        // Honeypot Attack Simulation Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3E0))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "🪤 Decepção Cibernética (Honeypot)",
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE65100),
                        fontSize = 16.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Simula a ação de um invasor invocando DebugSecurityOverride.disableSslPinning() via Frida ou Xposed.",
                        fontSize = 12.sp,
                        color = Color(0xFF5D4037)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = onHoneypotTriggered,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100))
                    ) {
                        Text("Disparar Honeypot Decoy Hook")
                    }
                }
            }
        }

        // Diagnostic Panel
        item {
            Text(
                text = "🔍 Painel de Telemetria e Diagnóstico",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        }

        diagnosticState?.let { state ->
            item {
                ProofHeaderCard(state.proofToken, state.diagnostic)
            }
            item {
                BiometricsCard(state.diagnostic.botScore, state.diagnostic.duressScore)
            }
            item {
                CanaryFlagsCard(state.unscrambledFlags)
            }
        } ?: run {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "Execute uma transferência Pix para emitir e inspecionar o envelope.",
                        color = Color.Gray,
                        fontSize = 14.sp
                    )
                }
            }
        }
    }
}

@Composable
fun ProofHeaderCard(token: String, diag: DecryptedProofDiagnostic) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "📦 X-MaigShield-Proof Envelope",
                color = Color(0xFF38BDF8),
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Token: ${token.take(48)}...",
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = Color.White
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Counter (Anti-Replay): #${diag.counter} | Version: ${diag.version}",
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                color = Color(0xFFE2E8F0)
            )
            Text(
                text = "Hardware Clock: ${diag.timestampNs} ns",
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = Color(0xFF94A3B8)
            )
            Text(
                text = "Request Hash: ${diag.bindingHashHex.take(24)}...",
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = Color(0xFF94A3B8)
            )
        }
    }
}

@Composable
fun BiometricsCard(botScore: Int, duressScore: Int) {
    val botColor = if (botScore > 100) Color(0xFFDC2626) else Color(0xFF16A34A)
    val duressColor = if (duressScore > 100) Color(0xFFEA580C) else Color(0xFF16A34A)

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("🤖 Bot Likelihood", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "$botScore / 255",
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                    color = botColor
                )
                Text(
                    text = if (botScore > 100) "Script / Emulador / Toque Sintético" else "Toque Humano Analógico",
                    fontSize = 11.sp,
                    color = Color.Gray
                )
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("⚠️ Índice de Coação", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "$duressScore / 255",
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                    color = duressColor
                )
                Text(
                    text = if (duressScore > 100) "Alerta de Coação / Tremor Anômalo" else "Padrão de Calmaria",
                    fontSize = 11.sp,
                    color = Color.Gray
                )
            }
        }
    }
}

@Composable
fun CanaryFlagsCard(flags: Long) {
    val checks = listOf(
        "Tracer Attached (TracerPid)" to (flags and 1L != 0L),
        "Frida Agent Mapped" to (flags and (1L shl 1) != 0L),
        "Xposed / LSPosed Mapped" to (flags and (1L shl 2) != 0L),
        "Substrate Mapped" to (flags and (1L shl 3) != 0L),
        "Anonymous Executable Memory" to (flags and (1L shl 4) != 0L),
        "Timing Anomaly (Stalker / DBI)" to (flags and (1L shl 5) != 0L),
        "Code Tampering / Checksum" to (flags and (1L shl 6) != 0L),
        "Honeypot Triggered" to (flags and (1L shl 7) != 0L),
        "Zygisk / Magisk Mapped" to (flags and (1L shl 8) != 0L),
        "Root Binary Present" to (flags and (1L shl 9) != 0L),
        "JNI Pointer Table Diverted" to (flags and (1L shl 10) != 0L),
        "KernelSU / APatch Mounts" to (flags and (1L shl 12) != 0L),
        "Frida Port Open (27042)" to (flags and (1L shl 13) != 0L),
        "Frida POSIX Thread Running" to (flags and (1L shl 14) != 0L),
        "Accessibility Abuse (Trojan)" to (flags and (1L shl 16) != 0L),
        "Screen Mirroring / VirtualDisplay" to (flags and (1L shl 17) != 0L),
        "Tapjacking (Window Obscured)" to (flags and (1L shl 18) != 0L),
        "Synthetic Non-Human Touch" to (flags and (1L shl 19) != 0L)
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Canary Bitmask Descriptografada",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
            Spacer(modifier = Modifier.height(8.dp))
            checks.forEach { (name, isTriggered) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(text = name, fontSize = 13.sp)
                    Box(
                        modifier = Modifier
                            .background(
                                color = if (isTriggered) Color(0xFFDC2626) else Color(0xFF16A34A),
                                shape = RoundedCornerShape(4.dp)
                            )
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = if (isTriggered) "TRIGGERED" else "CLEAR",
                            color = Color.White,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}
