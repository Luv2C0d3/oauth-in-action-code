"use strict";

const express = require("express");
const url = require("url");
const bodyParser = require("body-parser");
const randomstring = require("randomstring");
const cons = require("consolidate");
const nosql = require("nosql").load("database.nosql");
const querystring = require("querystring");

import { Request, Response } from "express";

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/authorizationServer");
app.set("json spaces", 4);

// authorization server information
const authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize",
  tokenEndpoint: "http://localhost:9001/token",
};

// client information
interface Client {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  scope: string;
}

const clients: Client[] = [
  {
    client_id: "oauth-client-1",
    client_secret: "oauth-client-secret-1",
    redirect_uris: ["http://localhost:9000/callback"],
    scope: "foo bar bazuka",
  },
];

const codes: { [key: string]: { request: any; scope: string[] } } = {};

const requests: { [key: string]: any } = {};

const getClient = (clientId: string): Client | undefined => {
  return clients.find((client) => client.client_id == clientId);
};

app.get("/", (req: Request, res: Response) => {
  res.render("index", { clients: clients, authServer: authServer });
});

app.get("/authorize", (req: Request, res: Response) => {
  const client = getClient(req.query.client_id as string);

  if (!client) {
    console.log("Unknown client %s", req.query.client_id);
    res.render("error", { error: "Unknown client" });
    return;
  } else if (!client.redirect_uris.includes(req.query.redirect_uri as string)) {
    console.log(
      "Mismatched redirect URI, expected %s got %s",
      client.redirect_uris,
      req.query.redirect_uri
    );
    res.render("error", { error: "Invalid redirect URI" });
    return;
  } else {
    /*
     * Validate that the set of scopes the client is requesting
     * aligns with the set of scopes the client is registered for.
     */
    const rscope = req.query.scope ? (req.query.scope as string).split(" ") : undefined;
    const cscope = client.scope ? client.scope.split(" ") : undefined;
    if (rscope && cscope && rscope.filter(item => !cscope.includes(item)).length > 0) {
      const urlParsed = buildUrl(req.query.redirect_uri as string, {
        error: "invalid_scope",
      });
      res.redirect(urlParsed);
      return;
    }
    const reqid = randomstring.generate(8);
    requests[reqid] = req.query;

    res.render("approve", { client: client, reqid: reqid, scope: rscope });
    return;

    /*
     * Send the requested scopes to the approval page for rendering
     */
  }
});

app.post("/approve", (req: Request, res: Response) => {
  const reqid = req.body.reqid as string;
  const query: any = requests[reqid];
  delete requests[reqid];

  if (!query) {
    // there was no matching saved request, this is an error
    res.render("error", { error: "No matching authorization request" });
    return;
  }

  if (req.body.approve) {
    if (query.response_type == "code") {
      // user approved access

      /*
       * Make sure the approved scopes from the form are allowed for this client
       */
      const rscope = getScopesFromForm(req.body);
      const client = getClient(query.client_id as string);
      const cscope = client?.scope ? client.scope.split(" ") : undefined;
      if (rscope && cscope && rscope.filter(item => !cscope.includes(item)).length > 0) {
        const urlParsed = buildUrl(query.redirect_uri as string, {
          error: "invalid_scope",
        });
        res.redirect(urlParsed);
        return;
      }
      console.log("Requested scopes ->", rscope);
      const code = randomstring.generate(8);

      // save the code and request for later

      /*
       * Save the approved scopes as part of this object
       */

      codes[code] = { request: query, scope: rscope };

      const urlParsed = buildUrl(query.redirect_uri as string, {
        code: code,
        state: query.state,
      });
      res.redirect(urlParsed);
      return;
    } else {
      // we got a response type we don't understand
      const urlParsed = buildUrl(query.redirect_uri as string, {
        error: "unsupported_response_type",
      });
      res.redirect(urlParsed);
      return;
    }
  } else {
    // user denied access
    const urlParsed = buildUrl(query.redirect_uri as string, {
      error: "access_denied",
    });
    res.redirect(urlParsed);
    return;
  }
});

app.post("/token", (req: Request, res: Response) => {
  const auth = req.headers["authorization"];
  let clientId: string | undefined;
  let clientSecret: string | undefined;

  if (auth) {
    // check the auth header
    const clientCredentials = decodeClientCredentials(auth);
    clientId = clientCredentials.id;
    clientSecret = clientCredentials.secret;
  }

  // otherwise, check the post body
  if (req.body.client_id) {
    if (clientId) {
      // if we've already seen the client's credentials in the authorization header, this is an error
      console.log("Client attempted to authenticate with multiple methods");
      res.status(401).json({ error: "invalid_client" });
      return;
    }

    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log("Unknown client %s", clientId);
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (client.client_secret != clientSecret) {
    console.log(
      "Mismatched client secret, expected %s got %s",
      client.client_secret,
      clientSecret
    );
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (req.body.grant_type == "authorization_code") {
    const code = codes[req.body.code as string];

    if (code) {
      delete codes[req.body.code as string]; // burn our code, it's been used
      if (code.request.client_id == clientId) {
        /*
         * Save the approved scopes as part of the token's structure
         */
        console.log("issuing token for these scopes --> ", code.scope);

        const access_token = randomstring.generate();
        const refresh_token = randomstring.generate();

        (nosql as any).insert({
          access_token: access_token,
          client_id: clientId,
          scope: code.scope,
        });
        (nosql as any).insert({
          refresh_token: refresh_token,
          client_id: clientId,
          scope: code.scope,
        });

        console.log("Issuing access token %s", access_token);

        /*
         * Return scopes as part of the token response
         */

        const token_response = {
          access_token: access_token,
          token_type: "Bearer",
          refresh_token: refresh_token,
          scope: code.scope.join(" "),
        };

        res.status(200).json(token_response);
        console.log("Issued tokens for code %s", req.body.code);

        return;
      } else {
        console.log(
          "Client mismatch, expected %s got %s",
          code.request.client_id,
          clientId
        );
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
    } else {
      console.log("Unknown code, %s", req.body.code);
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
  } else if (req.body.grant_type == "refresh_token") {
    (nosql as any).one().make((builder: any) => {
      builder.where("refresh_token", req.body.refresh_token);
      builder.callback((err: any, token: any) => {
        if (token) {
          console.log(
            "We found a matching refresh token: %s",
            req.body.refresh_token
          );
          if (token.client_id != clientId) {
            (nosql as any)
              .remove()
              .make((builderRemove: any) =>
                builderRemove.where("refresh_token", req.body.refresh_token)
              );
            res.status(400).json({ error: "invalid_grant" });
            return;
          }

          /*
           * Bonus: handle scopes for a refresh token request appropriately
           */

          const access_token = randomstring.generate();
          (nosql as any).insert({ access_token: access_token, client_id: clientId });
          const token_response = {
            access_token: access_token,
            token_type: "Bearer",
            refresh_token: token.refresh_token,
          };
          res.status(200).json(token_response);
          return;
        } else {
          console.log("No matching token was found.");
          res.status(400).json({ error: "invalid_grant" });
          return;
        }
      });
    });
  } else {
    console.log("Unknown grant type %s", req.body.grant_type);
    res.status(400).json({ error: "unsupported_grant_type" });
  }
});

const buildUrl = (base: string, options: { [key: string]: any }, hash?: string): string => {
  const newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  Object.entries(options).forEach(([key, value]) => {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

interface ClientCredentials {
  id: string;
  secret: string;
}

const decodeClientCredentials = (auth: string): ClientCredentials => {
  const clientCredentials = Buffer.from(auth.slice("basic ".length), "base64")
    .toString()
    .split(":");
  const clientId = querystring.unescape(clientCredentials[0]);
  const clientSecret = querystring.unescape(clientCredentials[1]);
  return { id: clientId, secret: clientSecret };
};

const getScopesFromForm = (body: any): string[] => {
  return Object.keys(body)
    .filter((key) => key.startsWith("scope_"))
    .map((key) => key.slice("scope_".length));
};

app.use("/", express.static("files/authorizationServer"));

// clear the database
nosql.clear();

const server = app.listen(9001, "localhost", () => {
  const host = (server.address() as any).address;
  const port = (server.address() as any).port;

  console.log(
    "OAuth Authorization Server is listening at http://%s:%s",
    host,
    port
  );
});