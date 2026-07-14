package com.adminsec.csrf;

import burp.api.montoya.*;
import burp.api.montoya.core.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
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
    private MontoyaApi api;
    private CsrfSettings settings;
    private TrafficContext context;
    private CsrfAnalyzer analyzer;
    private CandidateRepository repository;
    private ProjectStore store;
    private ExecutorService historyWorker;
    private ThreadPoolExecutor liveWorker;
    private volatile Future<?> scanTask;
    private final AtomicBoolean scanning = new AtomicBoolean();
    private final AtomicBoolean rescanRequested = new AtomicBoolean();
    private final AtomicBoolean cancelRequested = new AtomicBoolean();
    private CsrfPanel panel;
    private GuardedVerifier verifier;

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("CSRF Review Assistant");
        settings = CsrfSettings.load(api.persistence().preferences());
        context = new TrafficContext();
        analyzer = new CsrfAnalyzer(settings, context);
        repository = new CandidateRepository(settings.maxCandidates());
        try { store = new ProjectStore(api.persistence().extensionData()); }
        catch (RuntimeException unavailable) { store = new ProjectStore(null); }

        historyWorker = Executors.newSingleThreadExecutor(runnable -> daemon(runnable, "csrf-review-history"));
        liveWorker = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(500), runnable -> daemon(runnable, "csrf-review-live"),
                (task, executor) -> api.logging().logToError("CSRF live-analysis queue is full; a message was skipped."));
        verifier = new GuardedVerifier(api);
        panel = new CsrfPanel(api, settings, repository, store, this::scanHistory, this::cancelHistoryScan, verifier::prompt);
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("CSRF Review", panel);
        api.userInterface().registerContextMenuItemsProvider(new Menu());
        api.proxy().registerResponseHandler(new LiveHandler());
        api.http().registerHttpHandler(new AllToolsHandler());
        registerWebSockets();
        registerScanner();
        api.extension().registerUnloadingHandler(this::unload);
        api.logging().logToOutput("CSRF Review Assistant 1.1.0 loaded. Passive by default; guarded active verification is disabled by default.");
        scanHistory();
    }

    private static Thread daemon(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        return thread;
    }

    private void unload() {
        Future<?> task = scanTask;
        if (task != null) task.cancel(true);
        if (historyWorker != null) historyWorker.shutdownNow();
        if (liveWorker != null) liveWorker.shutdownNow();
        if (verifier != null) verifier.close();
    }

    private void registerScanner() {
        try {
            api.scanner().registerPassiveScanCheck(new PassiveCheck(), ScanCheckType.PER_REQUEST);
            api.logging().logToOutput("Passive Scanner integration enabled.");
        } catch (RuntimeException | LinkageError unavailable) {
            api.logging().logToOutput("Scanner integration unavailable; standalone Community-compatible tab remains active.");
        }
    }

    private void registerWebSockets() {
        try {
            api.websockets().registerWebSocketCreatedHandler(created -> {
                HttpResponse handshake = HttpResponse.httpResponse("HTTP/1.1 101 Switching Protocols\r\n\r\n");
                enqueue(httpRequestResponse(created.upgradeRequest(), handshake), false);
            });
            api.logging().logToOutput("Passive WebSocket CSWSH handshake analysis enabled.");
        } catch (RuntimeException | LinkageError unavailable) {
            api.logging().logToOutput("WebSocket integration unavailable.");
        }
    }

    private void scanHistory() {
        if (!scanning.compareAndSet(false, true)) {
            rescanRequested.set(true);
            cancelHistoryScan();
            return;
        }
        cancelRequested.set(false);
        panel.updateScanStatus("Starting history scan…");
        try {
            scanTask = historyWorker.submit(this::runHistoryScan);
        } catch (RejectedExecutionException error) {
            scanning.set(false);
            panel.updateScanStatus("History worker unavailable");
            api.logging().logToError("Unable to start CSRF history scan", error);
        }
    }

    private void runHistoryScan() {
        int count = 0, visited = 0, total = 0;
        repository.clear(false);
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history(item -> item.hasResponse()
                    && (!settings.scopeOnly() || item.finalRequest().isInScope()));
            int from = Math.max(0, history.size() - settings.historyLimit());
            List<ProxyHttpRequestResponse> selected = history.subList(from, history.size());
            total = selected.size();
            for (ProxyHttpRequestResponse item : selected) {
                if (Thread.currentThread().isInterrupted() || cancelRequested.get()) break;
                visited++;
                accept(httpRequestResponse(item.finalRequest(), item.response(), item.annotations()), false, false);
                count++;
                if (visited % 200 == 0) {
                    repository.changed();
                    panel.updateScanStatus("Scanning " + visited + "/" + total + " — " + repository.size() + " candidates");
                }
            }
            api.logging().logToOutput("CSRF history scan finished: " + count + " messages, " + repository.size()
                    + " unique candidates, " + repository.droppedCount() + " dropped by candidate limit.");
        } catch (RuntimeException error) {
            api.logging().logToError("CSRF history scan failed", error);
        } finally {
            repository.changed();
            boolean cancelled = Thread.currentThread().isInterrupted() || cancelRequested.get();
            panel.updateScanStatus((cancelled ? "Scan cancelled — " : "Scan complete — ") + repository.size()
                    + " candidates" + (repository.droppedCount() > 0 ? " (limit reached)" : ""));
            scanning.set(false);
            if (rescanRequested.getAndSet(false)) scanHistory();
        }
    }

    private void cancelHistoryScan() {
        Future<?> task = scanTask;
        if (task != null && !task.isDone()) {
            panel.updateScanStatus("Cancelling scan…");
            cancelRequested.set(true);
        }
    }

    private Optional<Assessment> accept(HttpRequestResponse message, boolean annotate, boolean notify) {
        return accept(message, annotate, notify, false);
    }

    private Optional<Assessment> accept(HttpRequestResponse message, boolean annotate, boolean notify, boolean alreadyRetained) {
        if (message == null || message.request() == null
                || (settings.scopeOnly() && !message.request().isInScope())) return Optional.empty();
        try {
            AnalysisInput input = MessageAdapter.input(message, settings.maxBodyBytes());
            Optional<Assessment> result = analyzer.analyze(input);
            // Response cookies and HTML tokens can only affect later requests, not the
            // request that produced this response.
            context.observe(input.url(), input.host(), input.path(), input.responseBody(), input.setCookieHeaders());
            result.ifPresent(assessment -> {
                HttpRequestResponse retained;
                try { retained = alreadyRetained ? message : message.copyToTempFile(); }
                catch (RuntimeException unavailable) { retained = message; }
                Candidate candidate = new Candidate(assessment.endpointKey(), assessment, retained,
                        store.status(assessment.endpointKey()), store.note(assessment.endpointKey()));
                repository.upsert(candidate, notify);
                if (annotate && assessment.priority() == Priority.REVIEW_1) annotate(message.annotations());
            });
            return result;
        } catch (RuntimeException error) {
            api.logging().logToError("CSRF message analysis failed", error);
            return Optional.empty();
        }
    }

    private void enqueue(HttpRequestResponse message, boolean annotate) {
        try {
            HttpRequestResponse retained = message.copyToTempFile();
            liveWorker.execute(() -> accept(retained, annotate, true, true));
        } catch (RuntimeException error) {
            api.logging().logToError("Unable to queue CSRF message analysis", error);
        }
    }

    private void annotate(Annotations annotations) {
        String tag = "[CSRF Review] P1 candidate - manual verification required";
        if (!annotations.hasNotes() || !annotations.notes().contains(tag))
            annotations.setNotes(annotations.hasNotes() && !annotations.notes().isBlank() ? annotations.notes() + " | " + tag : tag);
        if (!annotations.hasHighlightColor() || annotations.highlightColor() == HighlightColor.NONE)
            annotations.setHighlightColor(HighlightColor.MAGENTA);
    }

    private final class LiveHandler implements ProxyResponseHandler {
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
            enqueue(httpRequestResponse(response.initiatingRequest(), response, response.annotations()), true);
            return ProxyResponseReceivedAction.continueWith(response, response.annotations());
        }
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
            return ProxyResponseToBeSentAction.continueWith(response, response.annotations());
        }
    }

    private final class AllToolsHandler implements burp.api.montoya.http.handler.HttpHandler {
        public burp.api.montoya.http.handler.RequestToBeSentAction handleHttpRequestToBeSent(
                burp.api.montoya.http.handler.HttpRequestToBeSent request) {
            return burp.api.montoya.http.handler.RequestToBeSentAction.continueWith(request, request.annotations());
        }
        public burp.api.montoya.http.handler.ResponseReceivedAction handleHttpResponseReceived(
                burp.api.montoya.http.handler.HttpResponseReceived response) {
            ToolType tool = response.toolSource().toolType();
            if (settings.captureAllTools() && tool != ToolType.PROXY && tool != ToolType.SCANNER && tool != ToolType.EXTENSIONS) {
                enqueue(httpRequestResponse(response.initiatingRequest(), response, response.annotations()), false);
            }
            return burp.api.montoya.http.handler.ResponseReceivedAction.continueWith(response, response.annotations());
        }
    }

    private final class Menu implements ContextMenuItemsProvider {
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            Optional<HttpRequestResponse> selected = !event.selectedRequestResponses().isEmpty()
                    ? Optional.of(event.selectedRequestResponses().get(0))
                    : event.messageEditorRequestResponse().map(MessageEditorHttpRequestResponse::requestResponse);
            if (selected.isEmpty()) return List.of();
            JMenuItem analyze = new JMenuItem("Analyze with CSRF Review Assistant");
            analyze.addActionListener(eventListener -> enqueue(selected.get(), false));
            return List.of(analyze);
        }
    }

    private final class PassiveCheck implements PassiveScanCheck {
        public String checkName() { return "CSRF Review Assistant"; }
        public AuditResult doCheck(HttpRequestResponse message) {
            Optional<Assessment> result = accept(message, false, true);
            if (result.isEmpty() || result.get().priority() != Priority.REVIEW_1) return AuditResult.auditResult();
            Assessment assessment = result.get();
            String detail = "<p>A high-priority CSRF review candidate was identified. This passive result does not confirm a vulnerability.</p><ul>"
                    + assessment.reasons().stream().map(reason -> "<li>" + html(reason) + "</li>").reduce("", String::concat)
                    + "</ul><p>Manual verification of real server-side state is required.</p>";
            AuditIssue issue = AuditIssue.auditIssue("Potential CSRF protection gap (manual verification required)", detail,
                    "Use a session-bound unpredictable anti-CSRF token or a correctly enforced origin/Fetch Metadata policy, with SameSite as defense in depth.",
                    message.request().url(), AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
                    "Passive evidence only.", "Review generated variants safely and verify state changes.",
                    AuditIssueSeverity.INFORMATION, message);
            return AuditResult.auditResult(issue);
        }
        public ConsolidationAction consolidateIssues(AuditIssue existing, AuditIssue newer) {
            return existing.baseUrl().equals(newer.baseUrl()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
        }
    }

    private static String html(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
