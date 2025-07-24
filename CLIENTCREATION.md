I have an HTML template with a FORM (/app/templates/clientcreation_form.html), where I request information for the creation of Clients in an IDP.
The page should POST data to /clientcreation, where the backend process will handle the Client creation.
Now I only want to work in the HTML page, we will later focus on the backend.
The HTML form should have 2 sections.
First section should have:
- a SELECT input with the list of integration types, provided by utils.getIntegrationTypes(logger=utils.getLogger(), config=config)
- a SELECT input with the list of realm types, provided by utils.getRealmTypes(logger=utils.getLogger(), config=config)
- an input for Client name
- an input for Client owner email address

I will add other fields in the first section.

The second section should have the redirect_uri (one or many)
I want to use Flask WTF for it.
