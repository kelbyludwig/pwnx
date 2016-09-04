package burp;

import java.net.URL;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("pwnx");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
    }

    //doesNXDomain is a helper function that extracts
    //a domain name from a JavaScript include URL
    //and returns true if that domain name is not currently
    //registered to an IP address.
    private boolean doesNXDomain(String scriptSource)
    {
	try {
		URL url = new URL(scriptSource);
		InetAddress.getByName(url.getHost());
		return false;
	} catch(UnknownHostException ex) {
		return true;
	} catch(MalformedURLException ex) {
		return false;
	}

    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {

    	byte[] responseBytes = baseRequestResponse.getResponse();	    
	IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
	int offset = responseInfo.getBodyOffset();
	String httpBody = new String(responseBytes).substring(offset);
	Document doc = Jsoup.parse(httpBody);
	Elements elems = doc.select("script");

	if (elems.isEmpty()) {
		return null;
	} 

	List<IScanIssue> issues = new ArrayList<>();
	for (Element elem : elems) {

		if (elem.hasAttr("src")) {

			String scriptSource = elem.attr("src");

			if (scriptSource.charAt(0) == '/') {
				continue;
			} 

			if (doesNXDomain(scriptSource)) {
				int start = httpBody.indexOf(scriptSource) + offset;
				int end = start + scriptSource.length();
				List<int[]> markers = new ArrayList<int[]>();
				markers.add(new int[] { start, end });
        			issues.add(new CustomScanIssue(
        			        baseRequestResponse.getHttpService(),
        			        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
					new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, markers) }, 
        			        "Included JavaScript from NX Domain",
					"NX Domain for loaded JavaScript file: " + scriptSource,
        			        "High"));
			}
		}
	} 
	return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
	//NOTE(kkl): Uncertain if I want to filter duplicate issues. I feel it may lead to false negatives.
	return 0;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return "The application is loading JavaScript into its origin " + 
		"from a unresolvable domain. It is possible that this " + 
		"domain could be registered by an attacker and used to" + 
		" host malicous JavaScript.";
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}
