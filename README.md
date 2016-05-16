# Escc.BasicAuthentication.WebApi

An HTTP module which can be used to support basic authentication for an ASP.net web API. 

Create two complex keys and add them to the `apiuser` and `apikey` settings in `web.config`. You will need to pass the same values when calling your web API in order to authenticate. See [Escc.Umbraco.UserAccessWebService](https://github.com/east-sussex-county-council/Escc.Umbraco.UserAccessWebService) for an example.

The NuGet package is created using the [NuBuild](https://github.com/bspell1/NuBuild) extension for Visual Studio.