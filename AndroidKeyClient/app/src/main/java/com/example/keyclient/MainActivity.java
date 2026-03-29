package com.example.keyclient;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONObject;
import android.os.AsyncTask;

public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("keyclient");  // Load C++ lib
    }

    public native String verifyKey(String key, String server);
    public native String getHWID();

    private EditText keyInput;
    private TextView statusView, hwidView;
    private Button checkBtn;
    private final String SERVER = "http://103.249.201.186:5000";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        keyInput = findViewById(R.id.keyInput);
        statusView = findViewById(R.id.statusView);
        hwidView = findViewById(R.id.hwidView);
        checkBtn = findViewById(R.id.checkBtn);

        // Show HWID
        hwidView.setText("HWID: " + getHWID());

        checkBtn.setOnClickListener(v -> {
            String key = keyInput.getText().toString().trim();
            if (key.length() != 4) {
                Toast.makeText(this, "Key phải 4 chữ số", Toast.LENGTH_SHORT).show();
                return;
            }
            new CheckKeyTask().execute(key);
        });
    }

    private class CheckKeyTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... params) {
            return verifyKey(params[0], SERVER);
        }

        @Override
        protected void onPostExecute(String result) {
            try {
                JSONObject json = new JSONObject(result);
                String status = json.optString("status", "unknown");
                
                switch (status) {
                    case "success":
                        statusView.setText("✅ HỢP LỆ\nCòn lại: " + json.optString("remaining_hours", "∞") + " giờ");
                        statusView.setBackgroundColor(0xFF10B981);
                        break;
                    case "activated":
                        statusView.setText("🔓 KÍCH HOẠT OK");
                        statusView.setBackgroundColor(0xFF059669);
                        break;
                    case "expired":
                        statusView.setText("⏰ HẾT HẠN");
                        statusView.setBackgroundColor(0xFFF59E0B);
                        break;
                    case "invalid":
                        statusView.setText("❌ KEY SAI");
                        statusView.setBackgroundColor(0xEF4444);
                        break;
                    case "invalid_device":
                        statusView.setText("🔒 BIND MÁY KHÁC");
                        statusView.setBackgroundColor(0xFBBF24);
                        break;
                    default:
                        statusView.setText("⚠️ " + json.optString("message", "Lỗi"));
                        statusView.setBackgroundColor(0x6B7280);
                }
            } catch (Exception e) {
                statusView.setText("Lỗi: " + e.getMessage());
                statusView.setBackgroundColor(0xEF4444);
            }
        }
    }
}
