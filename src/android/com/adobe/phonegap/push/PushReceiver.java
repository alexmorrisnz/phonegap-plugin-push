package com.adobe.phonegap.push;

import me.pushy.sdk.Pushy;
import java.security.SecureRandom;
import android.content.Intent;
import android.graphics.Color;
import android.content.Context;
import android.content.Intent;
import android.app.PendingIntent;
import android.media.RingtoneManager;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.support.v4.app.NotificationCompat;

public class PushReceiver extends BroadcastReceiver implements PushConstants {

    @Override
    public void onReceive(Context context, Intent intent) {
        // Attempt to extract the "title" property from the data payload, or fallback to app shortcut label
        String notificationTitle = intent.getStringExtra("title") != null ? intent.getStringExtra("title") : context.getPackageManager().getApplicationLabel(context.getApplicationInfo()).toString();

        // Attempt to extract the "message" property from the data payload: {"message":"Hello World!"}
        String notificationText = intent.getStringExtra("message") != null ? intent.getStringExtra("message") : "Test notification";

        Intent notificationIntent = new Intent(context, PushHandlerActivity.class);
        notificationIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        SecureRandom random = new SecureRandom();
        int requestCode = random.nextInt();
        PendingIntent contentIntent = PendingIntent.getActivity(context, requestCode, notificationIntent,
        PendingIntent.FLAG_UPDATE_CURRENT);

        // Prepare a notification with vibration, sound and lights
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context)
                .setAutoCancel(true)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle(notificationTitle)
                .setContentText(notificationText)
                .setLights(Color.RED, 1000, 1000)
                .setVibrate(new long[]{0, 400, 250, 400})
                .setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION))
                .setContentIntent(contentIntent);

        // Automatically configure a Notification Channel for devices running Android O+
        Pushy.setNotificationChannel(builder, context);

        // Get an instance of the NotificationManager service
        NotificationManager notificationManager = (NotificationManager) context.getSystemService(context.NOTIFICATION_SERVICE);

        // Build the notification and display it
        notificationManager.notify(1, builder.build());
    }
    
}
