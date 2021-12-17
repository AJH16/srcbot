/*
 * KodeBlox Copyright 2017 Sayak Mukhopadhyay
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: //www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Router, Request, Response, NextFunction } from 'express';
import * as oa from 'simple-oauth2';
import { RestClient, IRestResponse } from 'typed-rest-client';
import { BearerCredentialHandler  } from 'typed-rest-client/Handlers';
import { FrontierSecrets } from '../secrets';

export class IndexRouter {
    router: Router;

    constructor() {
        this.router = Router();
        this.init();
    }

    public getAll(req: Request, res: Response, next: NextFunction) {
        res.send('Hello World');
    }

    public async processToken(req: Request, res: Response, next: NextFunction) {
        let oAuthClientOption: oa.ModuleOptions = {
            client:
            {
                id: FrontierSecrets.clientId,
                secret: FrontierSecrets.clientSecret
            },
            auth:
            {
                tokenHost: 'https://auth.frontierstore.net',
                tokenPath: '/token'
            },
            options:
            {
                authorizationMethod: 'body'
            }
        };

        let oAuthClient: oa.AuthorizationCode = new oa.AuthorizationCode(oAuthClientOption);
        let tokenConfig: oa.AuthorizationTokenConfig = 
        {
            code: req.query.code.toString(),
            redirect_uri: FrontierSecrets.redirectURL,
            scope: ['CAPI'],
        };
        let accessToken: oa.AccessToken;
        try {
            accessToken = await oAuthClient.getToken(tokenConfig,{json: true});
          } catch (error) {
            console.log('Access Token Error', error.message);
          }

        let bearerHandler: BearerCredentialHandler = new BearerCredentialHandler(accessToken.token.access_token, true);
        let rest: RestClient = new RestClient('srcbot','https://companion.orerve.net/', [bearerHandler]);
        let result: IRestResponse<EliteProfile> = await rest.get<EliteProfile>('/profile');
        
        res.send('Process My Token');
    }

    init() {
        this.router.get('/', this.getAll);
        this.router.get('/callback', this.processToken);
    }
}

interface EliteProfile{
    commander: Commander
}

interface Commander{
    name: String
}

const indexRoutes = new IndexRouter();

export default indexRoutes.router;
