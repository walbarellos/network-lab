package com.netwatch.app.data

data class WifiDevice(
    val ssid: String,
    val bssid: String,
    val capabilities: String,
    val frequency: Int,
    val level: Int,
    val channelWidth: Int,
    val timestamp: String
)
