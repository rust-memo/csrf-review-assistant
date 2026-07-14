package com.adminsec.csrf;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.adminsec.csrf.model.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.file.Path;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;

public final class CsrfPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private final MontoyaApi api;
    private final CsrfSettings settings;
    private final CandidateRepository repository;
    private final ProjectStore store;
    private final Runnable rescan;
    private final Runnable cancelScan;
    private final Consumer<Candidate> activeVerifier;
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);
    private final JTextField search = new JTextField(22);
    private final JComboBox<String> priorityFilter = new JComboBox<>(new String[]{"All", "Needs review", "P1", "P2", "P3", "Protection observed"});
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextArea evidence = new JTextArea();
    private final JTextArea note = new JTextArea(3, 30);
    private final JComboBox<ReviewStatus> status = new JComboBox<>(ReviewStatus.values());
    private final JLabel scanStatus = new JLabel("Ready");

    public CsrfPanel(MontoyaApi api, CsrfSettings settings, CandidateRepository repository, ProjectStore store,
                     Runnable rescan, Runnable cancelScan, Consumer<Candidate> activeVerifier) {
        super(new BorderLayout(6, 6)); this.api = api; this.settings = settings; this.repository = repository;
        this.store = store; this.rescan = rescan; this.cancelScan = cancelScan; this.activeVerifier = activeVerifier;
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        build(); repository.addListener(this::refresh); refresh();
    }

    private void build() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton rescanButton = new JButton("Rescan history"), cancel = new JButton("Cancel scan");
        JButton variants = new JButton("Send test variants to Repeater"), verify = new JButton("Guarded active verification"), poc = new JButton("Generate PoC");
        JButton export = new JButton("Export"), settingsButton = new JButton("Settings");
        top.add(new JLabel("Search:")); top.add(search); top.add(priorityFilter); top.add(rescanButton); top.add(cancel);
        top.add(variants); top.add(verify); top.add(poc); top.add(export); top.add(settingsButton); top.add(scanStatus);
        add(top, BorderLayout.NORTH);

        table.setRowSorter(sorter); table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelection(); });
        JScrollPane tableScroll = new JScrollPane(table); tableScroll.setPreferredSize(new Dimension(1000, 260));
        evidence.setEditable(false); evidence.setLineWrap(true); evidence.setWrapStyleWord(true);
        JTabbedPane messages = new JTabbedPane(); messages.addTab("Request", requestEditor.uiComponent()); messages.addTab("Response", responseEditor.uiComponent()); messages.addTab("Why flagged", new JScrollPane(evidence));
        JPanel review = new JPanel(new BorderLayout(5, 5)); JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton save = new JButton("Save review"); controls.add(new JLabel("Status:")); controls.add(status); controls.add(save); review.add(controls, BorderLayout.NORTH); review.add(new JScrollPane(note), BorderLayout.CENTER);
        JSplitPane lower = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, messages, review); lower.setResizeWeight(.78);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, lower); split.setResizeWeight(.45); add(split, BorderLayout.CENTER);

        DocumentListener filter = new DocumentListener() { public void insertUpdate(DocumentEvent e){applyFilter();} public void removeUpdate(DocumentEvent e){applyFilter();} public void changedUpdate(DocumentEvent e){applyFilter();} };
        search.getDocument().addDocumentListener(filter); priorityFilter.addActionListener(e -> applyFilter());
        rescanButton.addActionListener(e -> rescan.run()); cancel.addActionListener(e -> cancelScan.run());
        variants.addActionListener(e -> sendVariants()); verify.addActionListener(e -> verifySelected()); poc.addActionListener(e -> showPoc());
        export.addActionListener(e -> export()); settingsButton.addActionListener(e -> settingsDialog()); save.addActionListener(e -> saveReview());
    }

    private void refresh() { model.set(repository.snapshot()); applyFilter(); }
    private void applyFilter() {
        String query = search.getText().trim().toLowerCase(Locale.ROOT); String selected = Objects.toString(priorityFilter.getSelectedItem(), "All");
        sorter.setRowFilter(new RowFilter<>() {
            @Override public boolean include(Entry<? extends Model, ? extends Integer> entry) {
                Candidate c = model.at(entry.getIdentifier()); var a = c.assessment();
                boolean text = query.isBlank() || (a.endpointKey() + " " + a.actionType() + " " + a.authEvidence() + " "
                        + a.tokenEvidence() + " " + a.fetchMetadataEvidence() + " " + a.corsEvidence() + " " + c.status().label())
                        .toLowerCase(Locale.ROOT).contains(query);
                boolean priority = switch (selected) {
                    case "Needs review" -> a.priority() != Priority.PROTECTED;
                    case "P1" -> a.priority() == Priority.REVIEW_1; case "P2" -> a.priority() == Priority.REVIEW_2;
                    case "P3" -> a.priority() == Priority.REVIEW_3; case "Protection observed" -> a.priority() == Priority.PROTECTED; default -> true;
                }; return text && priority;
            }
        });
    }

    private Optional<Candidate> selected() {
        int row = table.getSelectedRow(); return row < 0 ? Optional.empty() : Optional.of(model.at(table.convertRowIndexToModel(row)));
    }
    private void showSelection() {
        selected().ifPresent(candidate -> {
            requestEditor.setRequest(candidate.message().request());
            responseEditor.setResponse(candidate.message().hasResponse() ? candidate.message().response() : HttpResponse.httpResponse());
            var a = candidate.assessment(); StringBuilder text = new StringBuilder("This is a passive candidate, not a confirmed vulnerability.\n\n");
            a.reasons().forEach(reason -> text.append("• ").append(reason).append('\n'));
            text.append("\nOrigin evidence: ").append(a.originEvidence())
                    .append("\nFetch Metadata: ").append(a.fetchMetadataEvidence())
                    .append("\nCORS evidence: ").append(a.corsEvidence())
                    .append("\nObserved: ").append(candidate.occurrences()).append(" time(s)")
                    .append("\n\nManual verification is required. Compare a valid control with generated variants and confirm the real server-side state.");
            evidence.setText(text.toString()); status.setSelectedItem(candidate.status()); note.setText(candidate.note());
        });
    }
    private void verifySelected() {
        selected().ifPresent(candidate -> {
            if (!settings.activeVerificationEnabled()) {
                message("Guarded active verification is disabled. Enable it explicitly in Settings after reviewing the safety warning.", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (!candidate.message().request().isInScope()) {
                message("Active verification is restricted to Target Scope.", JOptionPane.ERROR_MESSAGE);
                return;
            }
            activeVerifier.accept(candidate);
        });
    }
    private void sendVariants() {
        selected().ifPresent(candidate -> {
            for (TestVariantFactory.Variant variant : new TestVariantFactory().create(candidate.message().request(), candidate.assessment()))
                api.repeater().sendToRepeater(variant.request(), "CSRF " + variant.label());
            message("Variants were opened in Repeater. No request was sent.", JOptionPane.INFORMATION_MESSAGE);
        });
    }
    private void showPoc() {
        selected().ifPresent(candidate -> {
            Optional<String> generated = new PocGenerator().generate(candidate.message().request(), candidate.assessment().tokenName());
            if (generated.isEmpty()) { message("A reliable HTML PoC is not available for this Content-Type. Use the Repeater variants.", JOptionPane.WARNING_MESSAGE); return; }
            JTextArea area = new JTextArea(generated.get(), 26, 90); area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); area.setLineWrap(false);
            JButton copy = new JButton("Copy to clipboard"); copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(area.getText()), null));
            JPanel panel = new JPanel(new BorderLayout()); panel.add(new JScrollPane(area), BorderLayout.CENTER); panel.add(copy, BorderLayout.SOUTH);
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), panel, "Offline CSRF PoC — review before use", JOptionPane.PLAIN_MESSAGE);
        });
    }
    private void saveReview() {
        selected().ifPresent(candidate -> { ReviewStatus selectedStatus = (ReviewStatus) status.getSelectedItem(); candidate.review(selectedStatus, note.getText()); store.save(candidate.key(), selectedStatus, note.getText()); repository.changed(); });
    }
    private void export() {
        if (settings.includeNotesInExport()) {
            int confirmed = JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(),
                    "Reviewer notes may contain secrets that pattern-based redaction cannot recognize. Include notes in this export?",
                    "Confirm note export", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirmed != JOptionPane.YES_OPTION) return;
        }
        JFileChooser chooser = new JFileChooser(); chooser.setDialogTitle("Export redacted CSRF report (.json, .csv, .html)");
        if (chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION) return;
        try { new Exporter().export(chooser.getSelectedFile().toPath(), repository.snapshot(), settings.includeNotesInExport());
            message("Report exported without raw requests, cookies, authorization values, or token values. Notes included: " + settings.includeNotesInExport(), JOptionPane.INFORMATION_MESSAGE); }
        catch (Exception error) { api.logging().logToError("CSRF export failed", error); message("Export failed: " + error.getMessage(), JOptionPane.ERROR_MESSAGE); }
    }
    private void settingsDialog() {
        JCheckBox scope = new JCheckBox("Target Scope only", settings.scopeOnly());
        JCheckBox allTools = new JCheckBox("Analyze non-Proxy Burp tools", settings.captureAllTools());
        JCheckBox active = new JCheckBox("Enable guarded active verification (can be destructive)", settings.activeVerificationEnabled());
        JCheckBox exportNotes = new JCheckBox("Include reviewer notes in exports", settings.includeNotesInExport());
        JComboBox<CsrfSettings.Sensitivity> sensitivity = new JComboBox<>(CsrfSettings.Sensitivity.values()); sensitivity.setSelectedItem(settings.sensitivity());
        JSpinner history = new JSpinner(new SpinnerNumberModel(settings.historyLimit(), 100, 100_000, 100)); JSpinner body = new JSpinner(new SpinnerNumberModel(settings.maxBodyBytes(), 16_384, 10_485_760, 16_384));
        JSpinner candidates = new JSpinner(new SpinnerNumberModel(settings.maxCandidates(), 100, 50_000, 100));
        JTextArea token = area(settings.customTokenNames()), auth = area(settings.customAuthCookies()), words = area(settings.customSensitiveWords()), hosts = area(settings.ignoredHosts()), paths = area(settings.ignoredPaths());
        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6)); form.add(scope); form.add(allTools); form.add(active); form.add(exportNotes);
        form.add(new JLabel("Sensitivity")); form.add(sensitivity); form.add(new JLabel("History limit")); form.add(history);
        form.add(new JLabel("Maximum candidates")); form.add(candidates); form.add(new JLabel("Max body bytes")); form.add(body);
        form.add(new JLabel("Custom token names")); form.add(new JScrollPane(token)); form.add(new JLabel("Authentication cookie names")); form.add(new JScrollPane(auth)); form.add(new JLabel("Sensitive words")); form.add(new JScrollPane(words)); form.add(new JLabel("Ignored hosts")); form.add(new JScrollPane(hosts)); form.add(new JLabel("Ignored path fragments")); form.add(new JScrollPane(paths));
        if (JOptionPane.showConfirmDialog(api.userInterface().swingUtils().suiteFrame(), form, "CSRF Review Assistant settings", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
            settings.update(scope.isSelected(), (CsrfSettings.Sensitivity) sensitivity.getSelectedItem(),
                    (Integer) history.getValue(), (Integer) body.getValue(), (Integer) candidates.getValue(),
                    allTools.isSelected(), active.isSelected(), exportNotes.isSelected(), token.getText(), auth.getText(),
                    words.getText(), hosts.getText(), paths.getText());
            repository.setMaximumSize(settings.maxCandidates());
            settings.save(api.persistence().preferences()); rescan.run();
        }
    }
    private static JTextArea area(Collection<String> values) { return new JTextArea(String.join(", ", values), 2, 24); }
    private void message(String text, int type) { JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), text, "CSRF Review Assistant", type); }
    public void updateScanStatus(String value) {
        if (SwingUtilities.isEventDispatchThread()) scanStatus.setText(value);
        else SwingUtilities.invokeLater(() -> scanStatus.setText(value));
    }

    private static final class Model extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private final String[] columns = {"Priority", "Confidence", "Method / endpoint", "Action", "Authentication", "Token", "SameSite", "Exploitability", "Seen", "Status"};
        private List<Candidate> rows = List.of();
        void set(List<Candidate> values) { rows = List.copyOf(values); fireTableDataChanged(); }
        Candidate at(int row) { return rows.get(row); }
        public int getRowCount(){return rows.size();} public int getColumnCount(){return columns.length;} public String getColumnName(int c){return columns[c];}
        public Object getValueAt(int r, int c) { Candidate candidate = rows.get(r); var a = candidate.assessment(); return switch(c) {
            case 0 -> a.priority().label(); case 1 -> a.confidence(); case 2 -> a.endpointKey(); case 3 -> a.actionType(); case 4 -> a.authEvidence();
            case 5 -> a.tokenEvidence(); case 6 -> a.cookieDefense(); case 7 -> a.exploitability(); case 8 -> candidate.occurrences(); default -> candidate.status().label(); }; }
    }
}
