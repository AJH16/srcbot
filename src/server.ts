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

import * as express from 'express';
import * as logger from 'morgan';

import IndexRouter from './routes/index';
import { DiscordClient } from './modules/discord/client';
import { DB } from './db';
import { BugsnagClient } from './bugsnag';
import { BugsnagSecrets } from './secrets';

class App {
    public express: express.Application;
    public db: DB;
    public discordClient: DiscordClient;
    public bugsnagClient: BugsnagClient;
    private bugsnagClientMiddleware;

    constructor() {
        this.express = express();
        this.bugsnagClient = new BugsnagClient();
        if (BugsnagSecrets.use) {
            this.bugsnagClientMiddleware = this.bugsnagClient.client.getPlugin('express');
            this.express.use(this.bugsnagClientMiddleware.requestHandler);
        }
        this.middleware();
        this.routes();
        this.discordClient = new DiscordClient();
        this.db = new DB();
        this.setup()
    }

    private async setup() {
        await this.db.connectToDB()
    }

    private middleware(): void {
        if (BugsnagSecrets.use) {
            this.express.use(this.bugsnagClientMiddleware.errorHandler);
        }
        this.express.use(logger('dev'));
    }

    private routes(): void {
        this.express.use('/', IndexRouter);
    }
}

let app = new App();

export default app;
