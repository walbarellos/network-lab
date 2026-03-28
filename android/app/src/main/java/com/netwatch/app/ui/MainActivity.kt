package com.netwatch.app.ui

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.snackbar.Snackbar
import com.netwatch.app.R
import com.netwatch.app.data.WifiDevice
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var wifiManager: WifiManager
    private lateinit var listView: ListView
    private lateinit var statusText: TextView
    private lateinit var fabScan: FloatingActionButton

    private val devices = mutableListOf<WifiDevice>()
    private lateinit var adapter: ArrayAdapter<String>

    private val wifiScanReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val success = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false)
            if (success) {
                scanSuccess()
            } else {
                scanFailure()
            }
        }
    }

    private val locationPermissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        when {
            permissions.getOrDefault(Manifest.permission.ACCESS_FINE_LOCATION, false) -> {
                scanWifi()
            }
            permissions.getOrDefault(Manifest.permission.ACCESS_COARSE_LOCATION, false) -> {
                scanWifi()
            }
            else -> {
                Toast.makeText(this, "Permissão necessária para scan WiFi", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        listView = findViewById(R.id.list_devices)
        statusText = findViewById(R.id.text_status)
        fabScan = findViewById(R.id.fab_scan)

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, mutableListOf())
        listView.adapter = adapter

        fabScan.setOnClickListener {
            checkPermissionsAndScan()
        }

        updateStatus("Pronto para escanear")
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_about -> {
                Snackbar.make(findViewById(android.R.id.content), "NetWatch v2.1 - Monitor de Rede", Snackbar.LENGTH_LONG).show()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun checkPermissionsAndScan() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) 
                != PackageManager.PERMISSION_GRANTED) {
                locationPermissionRequest.launch(arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES))
                return
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) 
                != PackageManager.PERMISSION_GRANTED) {
                locationPermissionRequest.launch(arrayOf(
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION
                ))
                return
            }
        }
        scanWifi()
    }

    private fun scanWifi() {
        @Suppress("DEPRECATION")
        val success = wifiManager.startScan()
        if (!success) {
            scanFailure()
        }
    }

    private fun scanSuccess() {
        val results = wifiManager.scanResults
        devices.clear()
        
        val dateFormat = SimpleDateFormat("HH:mm", Locale.getDefault())
        
        for (result in results) {
            val device = WifiDevice(
                ssid = result.SSID.ifEmpty { "<Rede oculta>" },
                bssid = result.BSSID,
                capabilities = result.capabilities,
                frequency = result.frequency,
                level = result.level,
                channelWidth = result.channelWidth,
                timestamp = dateFormat.format(Date(result.timestamp / 1000))
            )
            devices.add(device)
        }

        devices.sortByDescending { it.level }

        updateList()
        updateStatus("Encontrados ${devices.size} dispositivos")
    }

    private fun scanFailure() {
        Toast.makeText(this, "Falha no scan WiFi", Toast.LENGTH_SHORT).show()
        updateStatus("Erro ao escanear")
    }

    private fun updateList() {
        adapter.clear()
        for (device in devices) {
            val signal = WifiSignal.getSignalLevel(device.level)
            val info = "${device.ssid}\n" +
                       "BSSID: ${device.bssid}\n" +
                       "Sinal: $signal | Canal: ${device.frequency}MHz | ${device.timestamp}"
            adapter.add(info)
        }
        adapter.notifyDataSetChanged()
    }

    private fun updateStatus(message: String) {
        statusText.text = message
    }

    override fun onResume() {
        super.onResume()
        val intentFilter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        registerReceiver(wifiScanReceiver, intentFilter)
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(wifiScanReceiver)
    }
}

object WifiSignal {
    fun getSignalLevel(rssi: Int): String {
        return when {
            rssi >= -50 -> "Excelente"
            rssi >= -60 -> "Bom"
            rssi >= -70 -> "Regular"
            else -> "Fraco"
        }
    }
}
