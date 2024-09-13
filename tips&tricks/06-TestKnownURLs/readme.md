Today, multiple repositories and methods exist for checking if your Azure Stack HCI host or hosts are able to access all of the URLs and ports that Azure Stack HCI needs to be able to access, both for deployment and for ongoing management activities.

This PowerShell Script is designed to consolidate a bunch of these disparate sources into one, simple to run script, which provides actionable output.

It also aims to pull definitive URLs out of the most recent version of the environment checker, and replace wildcard URLs listed in the public GitHub repositories with those testable, more definitive URLs and ports.

There is a section which tests URLs/ports required for the Dell APEX Cloud Platform for Microsoft Azure. If you do not need to test these, you can comment this section out.

This is intended to provide a starting point, into which you the community can contribute your experience to augment the testing done here. Please open pull requests to make any changes to the script, or additions to URL tests as appropriate - this is not a static space, and sharing knowledge and building together is how we'll build the most robust community tooling for this ecosystem.

The Script is available [here](AzSHCIURLTester.ps1).

Notes:

* In the [GitHub repositories](https://github.com/Azure/AzureStack-Tools/blob/master/HCI/EastUSendpoints/eastus-hci-endpoints.md), there are some URLs listed which ask for both port 80 and 443, in which 80 does not work.
* These will always show as failures, currently they are *.prod.hot.ingest.monitor.core.windows.net, *.delivery.mp.microsoft.com, *.prod.do.dsp.mp.microsoft.com, and *.endpoint.security.microsoft.com.
* You can probably safely ignore these, but they're still shown for completeness. 

* waconazure.com is not testable prior to deployment, so is skipped.

* wustat.microsoft.com is listed in GitHub, but does not resolve.

* <yourarcgatewayendpointid>.gw.arc.azure.net is skipped as it's only relevant when using the Arc Gateway - testing Arc Gateway connectivity will require a separate script. 
