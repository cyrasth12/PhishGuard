package com.phishguard.model;

/**
 * Metric breakdown extracted from analyzing the URL string structure.
 */
public class UrlMetrics {
    private String rawUrl;
    private String protocol;
    private String host;
    private int port;
    private String path;
    private double entropy;
    private int subdomainCount;
    private boolean isIpHost;
    private boolean isHomoglyphDetected;
    private boolean isTyposquatDetected;
    private String suspectedTargetBrand;
    private boolean isSuspiciousTld;

    public UrlMetrics() {}

    // Getters and Setters
    public String getRawUrl() { return rawUrl; }
    public void setRawUrl(String rawUrl) { this.rawUrl = rawUrl; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public double getEntropy() { return entropy; }
    public void setEntropy(double entropy) { this.entropy = entropy; }

    public int getSubdomainCount() { return subdomainCount; }
    public void setSubdomainCount(int subdomainCount) { this.subdomainCount = subdomainCount; }

    public boolean isIpHost() { return isIpHost; }
    public void setIpHost(boolean ipHost) { isIpHost = ipHost; }

    public boolean isHomoglyphDetected() { return isHomoglyphDetected; }
    public void setHomoglyphDetected(boolean homoglyphDetected) { isHomoglyphDetected = homoglyphDetected; }

    public boolean isTyposquatDetected() { return isTyposquatDetected; }
    public void setTyposquatDetected(boolean typosquatDetected) { isTyposquatDetected = typosquatDetected; }

    public String getSuspectedTargetBrand() { return suspectedTargetBrand; }
    public void setSuspectedTargetBrand(String suspectedTargetBrand) { this.suspectedTargetBrand = suspectedTargetBrand; }

    public boolean isSuspiciousTld() { return isSuspiciousTld; }
    public void setSuspiciousTld(boolean suspiciousTld) { isSuspiciousTld = suspiciousTld; }
}
