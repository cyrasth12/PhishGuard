package com.phishguard.model;

/**
 * Request payload structure for scanner endpoints.
 */
public class ScanRequest {
    private String url;
    private String htmlContent; // Optional offline HTML payload for testing

    public ScanRequest() {}

    public ScanRequest(String url) {
        this.url = url;
    }

    public ScanRequest(String url, String htmlContent) {
        this.url = url;
        this.htmlContent = htmlContent;
    }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getHtmlContent() { return htmlContent; }
    public void setHtmlContent(String htmlContent) { this.htmlContent = htmlContent; }
}
