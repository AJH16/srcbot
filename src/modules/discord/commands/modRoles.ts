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

import App from '../../../server';
import { Responses } from '../responseDict';
import { DB } from '../../../db';
import { Access } from '../access';
import { Message, MessageEmbed, Permissions } from 'discord.js';
import { Command } from "../../../interfaces/Command";

export class ModRoles implements Command {
    db: DB;
    dmAble = false;

    constructor() {
        this.db = App.db;
    }

    exec(message: Message, commandArguments: string): void {
        let argsArray: string[] = [];
        if (commandArguments.length !== 0) {
            argsArray = commandArguments.split(" ");
        }
        try {
            if (argsArray.length > 0) {
                let command = argsArray[0].toLowerCase();
                command = this.checkAndMapAlias(command);
                if (this[command]) {
                    this[command](message, argsArray);
                } else {
                    message.channel.send(Responses.getResponse(Responses.NOTACOMMAND));
                }
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            App.bugsnagClient.call(err);
        }
    }

    checkAndMapAlias(command: string) {
        switch (command) {
            case 'a':
                return 'add';
            case 'r':
                return 'remove';
            case 'l':
                return 'list';
            default:
                return command;
        }
    }

    async add(message: Message, argsArray: string[]) {
        try {
            await Access.has(message.author, message.guild, [Access.ADMIN, Access.FORBIDDEN], true);
            if (argsArray.length === 2) {
                let guildId = message.guild.id;
                let modRoleId = argsArray[1];

                if (message.guild.roles.cache.has(modRoleId)) {
                    try {
                        let guild = await this.db.model.guild.findOneAndUpdate(
                            {guild_id: guildId},
                            {
                                updated_at: new Date(),
                                $addToSet: {mod_roles_id: modRoleId}
                            });
                        if (guild) {
                            message.channel.send(Responses.getResponse(Responses.SUCCESS));
                        } else {
                            try {
                                await message.channel.send(Responses.getResponse(Responses.FAIL));
                                message.channel.send(Responses.getResponse(Responses.GUILDNOTSETUP));
                            } catch (err) {
                                App.bugsnagClient.call(err, {
                                    metaData: {
                                        guild: guild._id
                                    }
                                });
                            }
                        }
                    } catch (err) {
                        message.channel.send(Responses.getResponse(Responses.FAIL));
                        App.bugsnagClient.call(err);
                    }
                } else {
                    message.channel.send(Responses.getResponse(Responses.IDNOTFOUND));
                }
            } else if (argsArray.length > 2) {
                message.channel.send(Responses.getResponse(Responses.TOOMANYPARAMS));
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            message.channel.send(Responses.getResponse(Responses.INSUFFICIENTPERMS));
        }
    }

    async remove(message: Message, argsArray: string[]) {
        try {
            await Access.has(message.author, message.guild, [Access.ADMIN, Access.FORBIDDEN], true);
            if (argsArray.length === 2) {
                let guildId = message.guild.id;
                let modRoleId = argsArray[1];

                try {
                    let guild = await this.db.model.guild.findOneAndUpdate(
                        {guild_id: guildId},
                        {
                            updated_at: new Date(),
                            $pull: {mod_roles_id: modRoleId}
                        });
                    if (guild) {
                        message.channel.send(Responses.getResponse(Responses.SUCCESS));
                    } else {
                        try {
                            await message.channel.send(Responses.getResponse(Responses.FAIL));
                            message.channel.send(Responses.GUILDNOTSETUP);
                        } catch (err) {
                            App.bugsnagClient.call(err, {
                                metaData: {
                                    guild: guild._id
                                }
                            });
                        }
                    }
                } catch (err) {
                    message.channel.send(Responses.getResponse(Responses.FAIL));
                    App.bugsnagClient.call(err);
                }
            } else if (argsArray.length > 2) {
                message.channel.send(Responses.getResponse(Responses.TOOMANYPARAMS));
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            message.channel.send(Responses.getResponse(Responses.INSUFFICIENTPERMS));
        }
    }

    async list(message: Message, argsArray: string[]) {
        try {
            await Access.has(message.author, message.guild, [Access.ADMIN, Access.FORBIDDEN], true);
            if (argsArray.length === 1) {
                let guildId = message.guild.id;

                try {
                    let guild = await this.db.model.guild.findOne({guild_id: guildId});
                    if (guild) {
                        if (guild.mod_roles_id && guild.mod_roles_id.length !== 0) {
                            let embed = new MessageEmbed();
                            embed.setTitle("Mod Roles");
                            embed.setColor([255, 0, 255]);
                            let idList = "";
                            guild.mod_roles_id.forEach(id => {
                                if (message.guild.roles.cache.has(id)) {
                                    idList += `${id} - @${message.guild.roles.cache.get(id).name}\n`;
                                } else {
                                    idList += `${id} - Does not exist in Discord. Please delete this from SRCBot`;
                                }
                            });
                            embed.addField("Ids and Names", idList);
                            embed.setTimestamp(new Date());
                            try {
                                message.channel.send(embed);
                            } catch (err) {
                                App.bugsnagClient.call(err, {
                                    metaData: {
                                        guild: guild._id
                                    }
                                });
                            }
                        } else {
                            try {
                                await message.channel.send(Responses.getResponse(Responses.FAIL));
                                message.channel.send("You don't have any mod roles set up");
                            } catch (err) {
                                App.bugsnagClient.call(err, {
                                    metaData: {
                                        guild: guild._id
                                    }
                                });
                            }
                        }
                    } else {
                        try {
                            await message.channel.send(Responses.getResponse(Responses.FAIL));
                            message.channel.send(Responses.getResponse(Responses.GUILDNOTSETUP));
                        } catch (err) {
                            App.bugsnagClient.call(err, {
                                metaData: {
                                    guild: guild._id
                                }
                            });
                        }
                    }
                } catch (err) {
                    message.channel.send(Responses.getResponse(Responses.FAIL));
                    App.bugsnagClient.call(err);
                }
            } else if (argsArray.length > 1) {
                message.channel.send(Responses.getResponse(Responses.TOOMANYPARAMS));
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            message.channel.send(Responses.getResponse(Responses.INSUFFICIENTPERMS));
        }
    }

    help(): [string, string, string, string[]] {
        return [
            'modroles(aliases: mrl)',
            'Adds, removes or lists the roles that should have moderating capability over SRCBot',
            'modroles <add|remove|list> <role id>\nmodroles <a|r|l> <role id>',
            [
                '`@SRCBot modroles add 1234564789012345678`',
                '`@SRCBot mrl a 1234564789012345678`',
                '`@SRCBot modroles remove 123456789012345678`',
                '`@SRCBot mrl remove 123456789012345678`',
                '`@SRCBot modroles list`',
                '`@SRCBot modroles l`'
            ]
        ];
    }
}
