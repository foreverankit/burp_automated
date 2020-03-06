package burp;

import java.util.*;

public class ScannerListener implements IScannerListener {

    ArrayList<IScanIssue> issues = new ArrayList<>();

    public void newScanIssue(IScanIssue issue) {
        issues.add(issue);
    }

    public IScanIssue[] getIssues() {
        return issues.toArray(new IScanIssue[0]);
    }


}
