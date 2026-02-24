package com.netwatch.companion

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * This service handles Firebase Cloud Messages. It is responsible for:
 * 1. Receiving new FCM registration tokens.
 * 2. Receiving incoming push notifications and displaying them on the device.
 */
class NetwatchFCMService : FirebaseMessagingService() {

    companion object {
        private const val TAG = "NetwatchFCMService"
        private const val CHANNEL_ID = "netwatch_alerts"
        private const val CHANNEL_NAME = "Netwatch Alerts"
    }

    /**
     * Called when a new FCM registration token is generated.
     *
     * This token is the unique identifier for this app instance that Netwatch needs
     * to send messages to this specific device.
     *
     * You should copy this token from your device's logcat and paste it into the
     * "FCM Token do Dispositivo" field in the Netwatch web UI.
     */
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        Log.d(TAG, "****************************************************************")
        Log.d(TAG, "NEW FCM TOKEN (COPY THIS TO NETWATCH): $token")
        Log.d(TAG, "****************************************************************")
    }

    /**
     * Called when a new message is received from FCM.
     *
     * It takes the notification payload from the message and displays it
     * as a standard system notification.
     */
    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        super.onMessageReceived(remoteMessage)
        Log.d(TAG, "FCM Message Received from: ${remoteMessage.from}")

        // Check if message contains a notification payload.
        remoteMessage.notification?.let {
            val title = it.title ?: "Netwatch Alert"
            val body = it.body ?: "You have a new message."
            Log.d(TAG, "Notification Title: $title")
            Log.d(TAG, "Notification Body: $body")
            sendNotification(title, body)
        }
    }

    /**
     * Creates and displays a system notification.
     *
     * @param title The title of the notification.
     * @param body The main text content of the notification.
     */
    private fun sendNotification(title: String, body: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create the NotificationChannel, but only on API 26+ because
        // NotificationChannel is new and not in the support library.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH)
            notificationManager.createNotificationChannel(channel)
        }

        val notificationBuilder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_notification) // Ensure you have this drawable
            .setContentTitle(title)
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)

        // The notification ID is a unique integer for each notification.
        notificationManager.notify(System.currentTimeMillis().toInt(), notificationBuilder.build())
    }
}

// Note: You will need a simple launcher icon for the app and a notification status bar icon.
// Create a simple icon and save it as `ic_stat_notification.xml` in your `res/drawable` folder.
// Example for a simple shield icon:
/*
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24.0"
    android:viewportHeight="24.0">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5L12,1z"/>
</vector>
*/
