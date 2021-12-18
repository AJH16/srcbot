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
import { BearerCredentialHandler } from 'typed-rest-client/Handlers';
import { FrontierSecrets } from '../secrets';
import * as nf from 'node-fetch';
import fetch from 'node-fetch';
import { profile } from 'console';
import { inRange } from 'lodash';

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
            accessToken = await oAuthClient.getToken(tokenConfig, { json: true });
        } catch (error) {
            console.log('Access Token Error', error.message);
        }

        let requestHeaders: nf.HeadersInit = new nf.Headers();
        requestHeaders.set('Content-Type', 'application/json');
        requestHeaders.set('Authorization', 'Bearer ' + accessToken.token.access_token);

        let requestInit: nf.RequestInit = {
            method: 'GET',
            headers: requestHeaders
        }

        // Get the user's profile for the commander name.
        let bearerHandler: BearerCredentialHandler = new BearerCredentialHandler(accessToken.token.access_token, true);
        let capiRest: RestClient = new RestClient('srcbot', 'https://companion.orerve.net/', [bearerHandler]);
        let result: IRestResponse<EliteProfile> = await capiRest.get<EliteProfile>('/profile');

        let commanderName: string = result.result.commander.name;
        let commanderId: number = result.result.commander.id;

        // Look up the most recent journal entry within the last 30 days to find the squadron name.
        let profileResult: nf.Response = await fetch('https://companion.orerve.net/journal', requestInit);
        let processDate: Date = new Date();
        let daysToSearch: number = 30;
        let squadronRegex: RegExp = new RegExp("\"event\":\"SquadronStartup\",\\s*\"SquadronName\":\"(?<SquadronName>[^\"]*)\".\\s*\"CurrentRank\":(?<Rank>\\d*)", "i");
        let squadronName: string = null;
        let squadronRank: string = null;
        let bodyText: string = null;
        let regexResult: RegExpExecArray = null;

        if (profileResult != null && profileResult.status == 200) {
            bodyText = await profileResult.text();
            regexResult = squadronRegex.exec(bodyText);
            if (regexResult != null) {
                squadronName = regexResult.groups.SquadronName;
                squadronRank = regexResult.groups.Rank;
            }
        }

        while (daysToSearch > 0 && squadronName == null) {
            daysToSearch -= 1;
            processDate.setDate(processDate.getDate() - 1);
            profileResult = await fetch('https://companion.orerve.net/journal/' + processDate.getUTCFullYear() + '/' + (processDate.getUTCMonth() + 1) + '/' + processDate.getUTCDate(), requestInit);
            if (profileResult.status == 200) {
                bodyText = await profileResult.text();
                regexResult = squadronRegex.exec(bodyText);
                if (regexResult != null) {
                    squadronName = regexResult.groups.SquadronName;
                    squadronRank = regexResult.groups.Rank;
                }
            }
        }

        if (squadronName == null) {
            // Need to notify user to login to game so that we have a history to check.
            return;
        }

        debugger;
        let squadronRest: RestClient = new RestClient('srcbot', 'https://api.orerve.net', [bearerHandler]);
        const xboxResultPromise = IndexRouter.LookupSquadron('XBOX', squadronName, squadronRest, 50);
        const psnResultPromise = IndexRouter.LookupSquadron('PS4', squadronName, squadronRest, 50);
        const pcResultPromise = IndexRouter.LookupSquadron('PC', squadronName, squadronRest, 50);
        let xboxResult: SquadronSearchResult = await xboxResultPromise;
        let psnResult: SquadronSearchResult = await psnResultPromise;
        let pcResult: SquadronSearchResult = await pcResultPromise;
        let platform: string = null;
        let guildDetails: SquadronSearchResult = null;

        if (xboxResult != null) {
            platform = 'XBOX';
            guildDetails = xboxResult;
        }

        if (psnResult != null) {
            if (platform != null) {
                throw new Error('More than one squadron type was valid for this user.  This is unexpected.');
            }
            platform = "PSN";
            guildDetails = psnResult;
        }

        if (pcResult != null) {
            if (platform != null) {
                throw new Error('More than one squadron type was valid for this user.  This is unexpected.');
            }
            platform = "PC";
            guildDetails = pcResult;
        }

        res.send('You are [' + guildDetails.tag + ']' + commanderName + ' of ' + guildDetails.name + '.  You are rank ' + squadronRank + '.  You play on ' + platform + '.');
    }

    // Attempt to lookup the given squadron name on the given platform.
    private static async LookupSquadron(platform: string, squadronNameParam: string, restClient: RestClient, limit: number): Promise<SquadronSearchResult> {
        let squadronName: string = squadronNameParam.replace(/\s/g, '+');
        let done: boolean = false;
        let squadronLookup: IRestResponse<SquadronSearchResults> = await restClient.get<SquadronSearchResults>('/2.0/website/squadron/list?platform=' + platform + '&limit=' + limit + '&name=' + squadronName);
        while (!done) {
            for (const squadron of squadronLookup.result.squadrons) {
                if (squadron.name == squadronNameParam) {
                    // Now that we have the squadron, we need to check the members.
                    try {
                        let squadronMemberLookup: IRestResponse<SquadronMemberResults> = await restClient.get<SquadronMemberResults>('/2.0/website/squadron/member/list?squadronId=' + squadron.id);
                        if (squadronMemberLookup.statusCode == 200) {
                            return squadron;
                        }
                        else {
                            return null;
                        }
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
            if (squadronLookup.result.totalResults <= squadronLookup.result.offset + squadronLookup.result.limit) {
                done = true;
            }
            else {
                squadronLookup = await restClient.get<SquadronSearchResults>('/2.0/website/squadron/list?platform=' + platform + '&limit=' + limit + '&offset=' + (squadronLookup.result.offset + squadronLookup.result.limit) + '&name=' + squadronName);
            }
        }

        return null;
    }

    init() {
        this.router.get('/', this.getAll);
        this.router.get('/callback', this.processToken);
    }
}

interface SquadronMemberResults {

}

interface SquadronSearchResults {
    totalResults: number,
    offset: number,
    limit: number,
    squadrons: SquadronSearchResult[]
}

interface SquadronSearchResult {
    id: number,
    name: string,
    tag: string,
    ownerId: number,
    platform: string,
    created: string,
    acceptingNewMembers: number,
    powerName: string,
    superpowerName: string,
    factionName: string,
    userTags: number[],
    memberCount: number,
    onlineCount: number,
    pendingCount: number,
    full: boolean,
    current_season_trade_score: number,
    current_season_combat_score: number,
    current_season_exploration_score: number,
    current_season_cqc_score: number,
    current_season_bgs_score: number,
    current_season_powerplay_score: number,
    current_season_aegis_score: number,
    relevance: number
}


interface EliteProfile {
    commander: Commander
}

interface Commander {
    id: number,
    name: string
}

const indexRoutes = new IndexRouter();

export default indexRoutes.router;
