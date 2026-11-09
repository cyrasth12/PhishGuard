package com.phishguard.model;

/**
 * Metric breakdown extracted from parsing the HTML DOM & document body.
 */
public class ContentMetrics {
    private String pageTitle;
    private int formCount;
    private int passwordFieldCount;
    private boolean hasOffsiteFormAction;
    private boolean hasZeroFontObfuscation;
    private boolean hasCssHiddenOverlay;
    private boolean hasExternalScriptRatio;
    private boolean isBrandMetaMismatch;
    private String detectedFormActionDomain;

    public ContentMetrics() {}

    // Getters and Setters
    public String getPageTitle() { return pageTitle; }
    public void setPageTitle(String pageTitle) { this.pageTitle = pageTitle; }

    public int getFormCount() { return formCount; }
    public void setFormCount(int formCount) { this.formCount = formCount; }

    public int getPasswordFieldCount() { return passwordFieldCount; }
    public void setPasswordFieldCount(int passwordFieldCount) { this.passwordFieldCount = passwordFieldCount; }

    public boolean isHasOffsiteFormAction() { return hasOffsiteFormAction; }
    public void setHasOffsiteFormAction(boolean hasOffsiteFormAction) { this.hasOffsiteFormAction = hasOffsiteFormAction; }

    public boolean isHasZeroFontObfuscation() { return hasZeroFontObfuscation; }
    public void setHasZeroFontObfuscation(boolean hasZeroFontObfuscation) { this.hasZeroFontObfuscation = hasZeroFontObfuscation; }

    public boolean isHasCssHiddenOverlay() { return hasCssHiddenOverlay; }
    public void setHasCssHiddenOverlay(boolean hasCssHiddenOverlay) { this.hasCssHiddenOverlay = hasCssHiddenOverlay; }

    public boolean isHasExternalScriptRatio() { return hasExternalScriptRatio; }
    public void setHasExternalScriptRatio(boolean hasExternalScriptRatio) { this.hasExternalScriptRatio = hasExternalScriptRatio; }

    public boolean isBrandMetaMismatch() { return isBrandMetaMismatch; }
    public void setBrandMetaMismatch(boolean brandMetaMismatch) { isBrandMetaMismatch = brandMetaMismatch; }

    public String getDetectedFormActionDomain() { return detectedFormActionDomain; }
    public void setDetectedFormActionDomain(String detectedFormActionDomain) { this.detectedFormActionDomain = detectedFormActionDomain; }
}
