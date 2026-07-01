package dev.guber.openformvault;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        TextView title = new TextView(this);
        title.setText("OpenFormVault");
        title.setTextSize(28);
        TextView subtitle = new TextView(this);
        subtitle.setText("Clean rewrite scaffold: local encrypted vault, sync, Autofill, RoboForm-style v1 scope.");
        subtitle.setTextSize(16);
        root.addView(title);
        root.addView(subtitle);
        setContentView(root);
    }
}
