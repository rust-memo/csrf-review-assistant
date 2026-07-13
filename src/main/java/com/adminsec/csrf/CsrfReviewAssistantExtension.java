package com.adminsec.csrf;

import burp.api.montoya.*;
import burp.api.montoya.core.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.scanner.*;
import burp.api.montoya.scanner.audit.issues.*;
import burp.api.montoya.scanner.scancheck.*;
import burp.api.montoya.ui.contextmenu.*;
import com.adminsec.csrf.model.*;

import javax.swing.*;
import java.awt.Component;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;

public final class CsrfReviewAssistantExtension implements BurpExtension {
    private MontoyaApi api; private CsrfSettings settings; private TrafficContext context; private CsrfAnalyzer analyzer;
    private CandidateRepository repository; private ProjectStore store; private ExecutorService worker; private final AtomicBoolean scanning = new AtomicBoolean();

    @Override public void initialize(MontoyaApi api) {
        this.api = api; api.extension().setName("CSRF Review Assistant"); settings = CsrfSettings.load(api.persistence().preferences());
        context = new TrafficContext(); analyzer = new CsrfAnalyzer(settings, context); repository = new CandidateRepository();
        try { store = new ProjectStore(api.persistence().extensionData()); } catch (RuntimeException unavailable) { store = new ProjectStore(null); }
        worker = Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "csrf-review-history"); t.setDaemon(true); return t; });
        CsrfPanel panel = new CsrfPanel(api, settings, repository, store, this::scanHistory); api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("CSRF Review", panel); api.userInterface().registerContextMenuItemsProvider(new Menu());
        api.proxy().registerResponseHandler(new LiveHandler()); registerScanner(); api.extension().registerUnloadingHandler(worker::shutdownNow);
        api.logging().logToOutput("CSRF Review Assistant 1.0 loaded. Passive analysis only; no test request is sent automatically."); scanHistory();
    }

    private void registerScanner() {
        try { api.scanner().registerPassiveScanCheck(new PassiveCheck(), ScanCheckType.PER_REQUEST); api.logging().logToOutput("Passive Scanner integration enabled."); }
        catch (RuntimeException | LinkageError unavailable) { api.logging().logToOutput("Scanner integration unavailable; standalone Community-compatible tab remains active."); }
    }
    private void scanHistory() {
        if (!scanning.compareAndSet(false, true)) { api.logging().logToOutput("CSRF history scan already running."); return; }
        repository.clear();
        worker.submit(() -> { int count = 0; try {
            List<ProxyHttpRequestResponse> history = api.proxy().history(); int from = Math.max(0, history.size() - settings.historyLimit());
            for (ProxyHttpRequestResponse item : history.subList(from, history.size())) { if (Thread.currentThread().isInterrupted()) break; if (item.hasResponse()) { accept(httpRequestResponse(item.finalRequest(), item.response(), item.annotations()), false); count++; } }
            api.logging().logToOutput("CSRF history scan finished: " + count + " messages, " + repository.snapshot().size() + " unique candidates.");
        } catch (RuntimeException error) { api.logging().logToError("CSRF history scan failed", error); } finally { scanning.set(false); } });
    }
    private Optional<Assessment> accept(HttpRequestResponse message, boolean annotate) {
        if (message == null || message.request() == null || (settings.scopeOnly() && !message.request().isInScope())) return Optional.empty();
        try {
            var input = MessageAdapter.input(message, settings.maxBodyBytes()); context.observe(input.host(), input.responseBody(), input.setCookieHeaders());
            Optional<Assessment> result = analyzer.analyze(input); result.ifPresent(assessment -> {
                Candidate candidate = new Candidate(assessment.endpointKey(), assessment, message, store.status(assessment.endpointKey()), store.note(assessment.endpointKey()));
                repository.upsert(candidate); if (annotate && assessment.priority() == Priority.REVIEW_1) annotate(message.annotations());
            }); return result;
        } catch (RuntimeException error) { api.logging().logToError("CSRF message analysis failed", error); return Optional.empty(); }
    }
    private void annotate(Annotations annotations) {
        String tag = "[CSRF Review] P1 candidate - manual verification required";
        if (!annotations.hasNotes() || !annotations.notes().contains(tag)) annotations.setNotes(annotations.hasNotes() && !annotations.notes().isBlank() ? annotations.notes() + " | " + tag : tag);
        if (!annotations.hasHighlightColor() || annotations.highlightColor() == HighlightColor.NONE) annotations.setHighlightColor(HighlightColor.MAGENTA);
    }

    private final class LiveHandler implements ProxyResponseHandler {
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) { accept(httpRequestResponse(response.initiatingRequest(), response, response.annotations()), true); return ProxyResponseReceivedAction.continueWith(response, response.annotations()); }
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) { return ProxyResponseToBeSentAction.continueWith(response, response.annotations()); }
    }
    private final class Menu implements ContextMenuItemsProvider {
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            Optional<HttpRequestResponse> selected = !event.selectedRequestResponses().isEmpty() ? Optional.of(event.selectedRequestResponses().get(0)) : event.messageEditorRequestResponse().map(MessageEditorHttpRequestResponse::requestResponse);
            if (selected.isEmpty()) return List.of(); JMenuItem analyze = new JMenuItem("Analyze with CSRF Review Assistant"); analyze.addActionListener(e -> accept(selected.get(), false)); return List.of(analyze);
        }
    }
    private final class PassiveCheck implements PassiveScanCheck {
        public String checkName() { return "CSRF Review Assistant"; }
        public AuditResult doCheck(HttpRequestResponse message) {
            Optional<Assessment> result = accept(message, false); if (result.isEmpty() || result.get().priority() != Priority.REVIEW_1) return AuditResult.auditResult();
            Assessment a = result.get(); String detail = "<p>A high-priority CSRF review candidate was identified. This passive result does not confirm a vulnerability.</p><ul>"
                    + a.reasons().stream().map(r -> "<li>" + html(r) + "</li>").reduce("", String::concat) + "</ul><p>Manual verification is required.</p>";
            AuditIssue issue = AuditIssue.auditIssue("Potential CSRF protection gap (manual verification required)", detail,
                    "Use a session-bound unpredictable anti-CSRF token and validate Origin as defense in depth.", message.request().url(),
                    AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE, "Passive evidence only.", "Review generated Repeater variants safely.", AuditIssueSeverity.INFORMATION, message);
            return AuditResult.auditResult(issue);
        }
        public ConsolidationAction consolidateIssues(AuditIssue existing, AuditIssue newer) { return existing.baseUrl().equals(newer.baseUrl()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH; }
    }
    private static String html(String value) { return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }
}
