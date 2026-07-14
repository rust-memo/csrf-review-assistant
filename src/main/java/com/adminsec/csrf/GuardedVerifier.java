package com.adminsec.csrf;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.adminsec.csrf.model.Candidate;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit, in-scope verification only. It never changes review status automatically. */
public final class GuardedVerifier implements AutoCloseable {
    private final MontoyaApi api;
    private final ExecutorService worker;
    private final AtomicBoolean running = new AtomicBoolean();

    public GuardedVerifier(MontoyaApi api) {
        this.api = api;
        this.worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "csrf-guarded-verification");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void prompt(Candidate candidate) {
        if (!candidate.message().request().isInScope()) {
            message("The selected request is outside Target Scope.", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (running.get()) {
            message("Another guarded verification is already running.", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<TestVariantFactory.Variant> variants = new TestVariantFactory().create(
                candidate.message().request(), candidate.assessment()).stream()
                .filter(variant -> !variant.label().startsWith("00 ")).toList();
        DefaultListModel<TestVariantFactory.Variant> model = new DefaultListModel<>();
        variants.forEach(model::addElement);
        JList<TestVariantFactory.Variant> list = new JList<>(model);
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        list.setCellRenderer((component, value, index, selected, focus) -> {
            JLabel label = new JLabel(value.label());
            label.setOpaque(true);
            label.setBackground(selected ? component.getSelectionBackground() : component.getBackground());
            label.setForeground(selected ? component.getSelectionForeground() : component.getForeground());
            return label;
        });
        JTextArea warning = new JTextArea(
                "Select only variants you understand. Sending any variant may repeat a password, payment, deletion, permission, or other destructive action.\n"
                        + "The captured response is used as the control; the original request is not resent. Redirects are not followed.\n"
                        + "Response similarity is evidence only and never confirms server-side state.", 5, 72);
        warning.setEditable(false); warning.setLineWrap(true); warning.setWrapStyleWord(true);
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.add(warning, BorderLayout.NORTH); panel.add(new JScrollPane(list), BorderLayout.CENTER);
        int choice = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(), panel,
                "Guarded active verification — select requests to SEND", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) return;
        List<TestVariantFactory.Variant> selected = list.getSelectedValuesList();
        if (selected.isEmpty()) {
            message("No variants selected; nothing was sent.", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int confirmed = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                "Send " + selected.size() + " modified request(s) now? This can change real server-side data.",
                "Final active verification confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.ERROR_MESSAGE);
        if (confirmed != JOptionPane.YES_OPTION || !running.compareAndSet(false, true)) return;

        try { worker.submit(() -> run(candidate, selected)); }
        catch (RejectedExecutionException unavailable) {
            running.set(false);
            message("Verification worker is unavailable; nothing was sent.", JOptionPane.ERROR_MESSAGE);
            return;
        }
        message("Verification started in the background. No original control request will be resent.", JOptionPane.INFORMATION_MESSAGE);
    }

    private void run(Candidate candidate, List<TestVariantFactory.Variant> selected) {
        StringBuilder report = new StringBuilder("Guarded verification results\n\n")
                .append("These response comparisons do not confirm whether server-side state changed.\n\n");
        int controlStatus = candidate.message().hasResponse() ? candidate.message().response().statusCode() : 0;
        int controlLength = candidate.message().hasResponse() ? candidate.message().response().body().length() : -1;
        report.append("Captured control: status=").append(controlStatus == 0 ? "none" : controlStatus)
                .append(", bodyBytes=").append(controlLength < 0 ? "unknown" : controlLength).append("\n");
        try {
            RequestOptions options = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER).withResponseTimeout(15_000);
            for (TestVariantFactory.Variant variant : selected) {
                if (Thread.currentThread().isInterrupted()) break;
                if (!variant.request().isInScope()) {
                    report.append("\n").append(variant.label()).append(": BLOCKED (outside Target Scope)");
                    continue;
                }
                try {
                    HttpRequestResponse result = api.http().sendRequest(variant.request(), options);
                    if (!result.hasResponse()) {
                        report.append("\n").append(variant.label()).append(": no response");
                        continue;
                    }
                    int status = result.response().statusCode(), length = result.response().body().length();
                    report.append("\n").append(variant.label()).append(": status=").append(status)
                            .append(", bodyBytes=").append(length)
                            .append(", statusMatchesControl=").append(controlStatus != 0 && status == controlStatus)
                            .append(", sizeSimilarity=").append(similarity(controlLength, length)).append('%');
                } catch (RuntimeException error) {
                    api.logging().logToError("Guarded CSRF verification failed for " + variant.label(), error);
                    report.append("\n").append(variant.label()).append(": failed (see extension error log)");
                }
            }
        } finally {
            running.set(false);
            SwingUtilities.invokeLater(() -> showReport(report.toString()));
        }
    }

    private void showReport(String value) {
        JTextArea area = new JTextArea(value, 24, 90);
        area.setEditable(false); area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), new JScrollPane(area),
                "Guarded verification evidence", JOptionPane.INFORMATION_MESSAGE);
    }
    private void message(String value, int type) {
        JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), value, "CSRF Review Assistant", type);
    }
    private static int similarity(int first, int second) {
        if (first < 0 || second < 0) return 0;
        if (first == 0 && second == 0) return 100;
        int max = Math.max(first, second), min = Math.min(first, second);
        return max == 0 ? 0 : (int) Math.round(100.0 * min / max);
    }

    @Override public void close() { worker.shutdownNow(); }
}
