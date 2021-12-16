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

import { Guild, User } from 'discord.js';
import App from '../../server';

export class Access {
    public static readonly ALL: string = "all";
    public static readonly ADMIN: string = "admin";
    public static readonly MOD: string = "mod";
    public static readonly SQUADRON_LEADER: string = "squadron";
    public static readonly FORBIDDEN: string = "forbidden";

    public static async has(author: User, guild: Guild, perms: string[], allowAdmin = false): Promise<boolean> {
        let member = guild.members.fetch(author)
        if (allowAdmin && (await member).permissions.has("ADMINISTRATOR")) {
            return true;
        } else {
            let loadedMember = await(member);
            let db = App.db;
            let guildId = loadedMember.guild.id;
            let roles = loadedMember.roles;
            let guild = await db.model.guild.findOne({guild_id: guildId});
            let bool = false;
            if (guild) {
                perms.forEach((permission, index) => {
                    switch (permission) {
                        case "all": {
                            bool = true;
                        }
                            break;
                        case "admin": {
                            let adminRoles = guild.admin_roles_id;
                            adminRoles.forEach((role, index) => {
                                if (roles.cache.has(role)) {
                                    bool = true;
                                }
                            });
                        }
                            break;
                        case "mod": {
                            let modRoles = guild.mod_roles_id;
                            modRoles.forEach((role, index) => {
                                if (roles.cache.has(role)) {
                                    bool = true;
                                }
                            });
                        }
                            break;
                        case "squadron": {
                            let squadronLeaderRoles = guild.squadron_leader_roles_id;
                            squadronLeaderRoles.forEach((role, index) => {
                                if (roles.cache.has(role)) {
                                    bool = true;
                                }
                            });
                        }
                        case "forbidden": {
                            let forbiddenRoles = guild.forbidden_roles_id;
                            forbiddenRoles.forEach((role, index) => {
                                if (roles.cache.has(role)) {
                                    bool = false;
                                }
                            });
                        }
                    }
                })
            }

            if (bool) {
                return true;
            } else {
                throw new Error('Access Denied');
            }
        }
    }
}
