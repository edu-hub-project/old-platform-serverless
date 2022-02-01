# old-platform-serverless

The serverless functions uploaded in the google cloud platform used now in the platform. The code is visible also there.
Since they are related to the "old" platform, they should not be included in the other repo for the "new" platform, where they will most likely not be used, that's why they are in a separate repository.

These functions do not need, at least for now, special updates or maintenance, and should be replaced with the "new" serverless function later.

They use the `config.yaml` file to read the secrets (this could be ported to the google secret manager), an example of the config file is uploaded (of course without the real values).

These functions are deployed as [HTTP trigger functions](https://cloud.google.com/functions/docs/calling/http#functions-calling-http-python) in the `europe-west3` region (Frankfurt) with `python3.8` via `gcloud` using the command (in this example for the `oc_get_participants_hybrid` function, but it's the same for the others also)

```
gcloud functions deploy oc_get_participants_hybrid \
--region europe-west3 --runtime python38 --trigger-http
```

In order to deploy via `gcloud`, you need to install the `gcloud` suite and activate your account on your computer.