package burp;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.Temporal;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.ParseException;

public class BurpExtender implements IBurpExtender, IHttpListener {

    private static final long TIMEOUT = 10;
    private static final String FORMAT_XML = "XML";
    private static final String FORMAT_HTML = "HTML";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private Config config;
    private ScannerListener scannerListener = new ScannerListener();
    private Temporal lastActivityTime = Instant.now();


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("Burp CLI");
        helpers = callbacks.getHelpers();
        createConfig();

        // if user doesn't provide url, for example if this is just regular BurpSuite start, abort further execution
        Optional<String> url = config.getOption(Config.URL);
        if(!url.isPresent()) {
            return;
        }

        scan(url.get());

        while(Duration.between(lastActivityTime, Instant.now()).getSeconds() < TIMEOUT) {
            pause(500);
        }

        report();

        callbacks.exitSuite(true);
    }


    private void pause(long timeout) {
        try {
            TimeUnit.MILLISECONDS.sleep(timeout);
        } catch (InterruptedException e) {}
    }

   // Method generating report
    private void report() {
        System.out.println("Report creation in process...");
        IScanIssue[] issues = scannerListener.getIssues();
        String format = config.getOption(Config.FORMAT).orElse("");
        format = format.toUpperCase();

        if(!format.equals(FORMAT_HTML) && !format.equals(FORMAT_XML)) {
            format = FORMAT_XML;
        }

        // default filename
        String filename = String.format("%s%s", "result.", format.toLowerCase());

        callbacks.generateScanReport(format, issues, new File(filename));
    }

    // Creating config instance
    private void createConfig() {
        try {
            config = new Config(callbacks.getCommandLineArguments());
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            config.printHelp();
            callbacks.exitSuite(false);
        }
    }


    private void scan(String url) {
        try {
            URL startURL = new URL(url);

            // if no spider just scan provided url
            callbacks.registerScannerListener(scannerListener);

            callbacks.registerHttpListener(this);
            doSpider(startURL);
        } catch (MalformedURLException e) {
            System.err.println("Provided Url is invalid.");
            System.err.println(e.getMessage());
            callbacks.exitSuite(false);
        }
    }


    private void doScan(URL url) {
        System.out.println("Scanning URL: " + url);
        String host = url.getHost();
        int port = url.getPort() > 0 ? url.getPort() : 80;
        String protocol = url.getProtocol();
        byte[] request = helpers.buildHttpRequest(url);
        doScan(host, port, protocol, request, null);
    }



    private void doScan(String host, int port, String protocol, byte[] request, byte[] response) {
        boolean isHttps = protocol.equalsIgnoreCase("https");

            doPassiveScan(host, port, isHttps, request, response);

    }





    // Performing scan(passive)
    private void doPassiveScan(String host, int port, boolean isHttps, byte[] request, byte[] response) {
        if(response == null) {
            response = callbacks.makeHttpRequest(host, port, isHttps, request);
        }
        callbacks.doPassiveScan(host, port, isHttps, request, response);
    }


    // Sending to spider
    private void doSpider(URL url) {
        if(!callbacks.isInScope(url)) {
            callbacks.includeInScope(getBaseUrl(url));
        }
        callbacks.sendToSpider(url);
    }

    // Getting Base url
    private URL getBaseUrl(URL url){
        try {
            return new URL(url, "/");
        } catch (MalformedURLException e) {
            // will not happen
        }
        return url;
    }

    // Sending to scanner
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        lastActivityTime = Instant.now();
        if(toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER && !messageIsRequest) {
            String host = messageInfo.getHttpService().getHost();
            int port = messageInfo.getHttpService().getPort();
            String protocol = messageInfo.getHttpService().getProtocol();
            doScan(host, port, protocol, messageInfo.getRequest(), messageInfo.getResponse());
        }
    }

}
