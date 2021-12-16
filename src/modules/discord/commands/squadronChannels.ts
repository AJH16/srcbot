/*
 * KodeBlox Copyright 2018 Sayak Mukhopadhyay
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

import { CategoryChannel, Message, MessageEmbed, Permissions, TextChannel } from 'discord.js';
import { sampleSize } from 'lodash';
import App from '../../../server';
import { Responses } from '../responseDict';
import { DB } from '../../../db';
import { Access } from '../access';
import { Command } from "../../../interfaces/Command";

export class SquadronChannels implements Command {
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
                command = SquadronChannels.checkAndMapAlias(command);
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

    private static checkAndMapAlias(command: string) {
        switch (command) {
            case 'rnd':
                return 'random';
            default:
                return command;
        }
    }

    async random(message: Message, argsArray: string[]) {
        try {
            await Access.has(message.author, message.guild, [Access.ADMIN, Access.MOD, Access.FORBIDDEN]);
            if (argsArray.length === 3) {
                let guildId = message.guild.id;
                let numberToSelect = +argsArray[1];
                let categoryToSelect = argsArray[2];
                try {
                    let flags = Permissions.FLAGS;
                    if (message.channel.type == "DM" || message.guild.me.permissionsIn(message.channel).has([flags.EMBED_LINKS])) {
                        let embed = await this.getRandomSquadronEmbed(guildId, message.channel as TextChannel, numberToSelect, categoryToSelect);
                        message.channel.send({embeds:[embed]});
                    } else {
                        try {
                            message.channel.send(Responses.getResponse(Responses.EMBEDPERMISSION));
                        } catch (err) {
                            App.bugsnagClient.call(err);
                        }
                    }
                } catch (err) {
                    message.channel.send(Responses.getResponse(Responses.FAIL));
                    App.bugsnagClient.call(err);
                }
            } else if (argsArray.length > 3) {
                message.channel.send(Responses.getResponse(Responses.TOOMANYPARAMS));
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            message.channel.send(Responses.getResponse(Responses.INSUFFICIENTPERMS));
        }
    }

    async create(message: Message, argsArray: string[]) {
        try {
            await Access.has(message.author, message.guild, [Access.ADMIN, Access.MOD, Access.SQUADRON_LEADER, Access.FORBIDDEN]);
            if (argsArray.length >= 4) {
                let guildId = message.guild.id;
                let platforms = argsArray[1].match(/.{1,2}/g);
                let categoryName = argsArray[2];
                let name = argsArray.slice(3);
                try {
                    let guild = await this.db.model.guild.findOne({guild_id: guildId});
                    if (guild) {
                        if (guild.squadron_platforms && guild.squadron_platforms.length !== 0) {
                            if (guild.squadron_channel_category_id && guild.squadron_channel_category_id.length !== 0) {
                                let categoryObject = this.getChannelCategoryFromName(message.channel as TextChannel, categoryName)
                                let count = 2
                                while (categoryObject.children.size === 50) {
                                    categoryObject = this.getChannelCategoryFromName(message.channel as TextChannel, categoryName, count)
                                    count++
                                }

                                if (platforms.every(platform => guild.squadron_platforms.includes(platform)) && categoryObject && guild.squadron_channel_category_id.findIndex(item => item === categoryObject.id) !== -1) {
                                    let channelName = `${name.join('-').toLowerCase()}-${platforms.sort().join('').toLowerCase()}`;
                                    if (message.guild.channels.cache.some(channel => channel.name === channelName)) {
                                        message.channel.send(Responses.getResponse(Responses.CHANNELEXISTS));
                                        return
                                    }
                                    await message.guild.channels.create(channelName, {
                                        parent: categoryObject,
                                        permissionOverwrites: [{
                                            id: message.author.id,
                                            allow: [Permissions.FLAGS.MANAGE_CHANNELS, Permissions.FLAGS.MANAGE_MESSAGES]
                                        }, ...categoryObject.permissionOverwrites.cache.values()]
                                    })
                                    await this.sortChannelCategory(message.guild.id, message.channel as TextChannel, categoryObject.id)
                                    message.channel.send(Responses.getResponse(Responses.SUCCESS));
                                } else if (!platforms.every(platform => guild.squadron_platforms.includes(platform))) {
                                    try {
                                        await message.channel.send(Responses.getResponse(Responses.FAIL));
                                        message.channel.send("Platform doesn't exist. Please contact a moderator for help.");
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
                                        message.channel.send("Category doesn't exist. Please contact a moderator for help.");
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
                                    message.channel.send("You don't have any squadron channel category ids set up");
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
                                message.channel.send("You don't have any squadron platforms set up");
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
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            message.channel.send(Responses.getResponse(Responses.INSUFFICIENTPERMS));
        }
    }

    async sort(message: Message, argsArray: string[]) {
        try {
            await Access.has(message.author, message.guild, [Access.ADMIN, Access.MOD, Access.FORBIDDEN]);
            if (argsArray.length === 2) {
                let guildId = message.guild.id;
                let categoryToSelect = argsArray[1];
                try {
                    let flags = Permissions.FLAGS;
                    if (message.channel.type == "DM" || message.guild.me.permissionsIn(message.channel).has([flags.MANAGE_CHANNELS])) {
                        await this.sortChannelCategory(guildId, message.channel as TextChannel, categoryToSelect);
                        message.channel.send(Responses.getResponse(Responses.SUCCESS));
                    } else {
                        try {
                            message.channel.send(Responses.getResponse(Responses.CHANNELPERMISSIONS));
                        } catch (err) {
                            App.bugsnagClient.call(err);
                        }
                    }
                } catch (err) {
                    message.channel.send(Responses.getResponse(Responses.FAIL));
                    App.bugsnagClient.call(err);
                }
            } else if (argsArray.length > 3) {
                message.channel.send(Responses.getResponse(Responses.TOOMANYPARAMS));
            } else {
                message.channel.send(Responses.getResponse(Responses.NOPARAMS));
            }
        } catch (err) {
            message.channel.send(Responses.getResponse(Responses.INSUFFICIENTPERMS));
        }
    }

    private async sortChannelCategory(guildId: string, channel: TextChannel, categoryToSelect: string) {
        let guild = await this.db.model.guild.findOne({guild_id: guildId});
        if (guild) {
            let categories: CategoryChannel[] = []
            if (categoryToSelect === 'all') {
                guild.squadron_channel_category_id.forEach(categoryId => {
                    categories.push(channel.guild.channels.cache.get(categoryId) as CategoryChannel)
                })
            } else {
                let index = guild.squadron_channel_category_id.indexOf(categoryToSelect)
                if (index >= 0) {
                    categories.push(channel.guild.channels.cache.get(categoryToSelect) as CategoryChannel)
                } else {
                    const categoryToSelectObject = this.getChannelCategoryFromName(channel, categoryToSelect)
                    if (categoryToSelectObject) {
                        categories.push(categoryToSelectObject)
                    } else {
                        await channel.send(Responses.getResponse(Responses.FAIL));
                        channel.send(Responses.getResponse(Responses.IDNOTFOUND));
                        return
                    }
                }
            }
            if (categories.length === 0) {
                await channel.send(Responses.getResponse(Responses.FAIL));
                channel.send(Responses.getResponse(Responses.IDNOTFOUND));
                return
            }
            for (const category of categories) {
                let channelsToSort = channel.guild.channels.cache.filter(channel => channel.parentId === category.id)
                channelsToSort.sort((firstChannel, secondChannel) => {
                    const firstChannelName = firstChannel.name.startsWith('💎') ? firstChannel.name.slice(2).toLowerCase() : firstChannel.name.toLowerCase()
                    const secondChannelName = secondChannel.name.startsWith('💎') ? secondChannel.name.slice(2).toLowerCase() : secondChannel.name.toLowerCase()
                    if (firstChannelName > secondChannelName) {
                        return 1
                    } else if (firstChannelName < secondChannelName) {
                        return -1
                    } else {
                        return 0
                    }
                });
                for (let i = 0; i < channelsToSort.size; i++) {
                    if (channelsToSort[i].position !== i) {
                        await channelsToSort[i].setPosition(i)
                    }
                }
            }
        } else {
            await channel.send(Responses.getResponse(Responses.FAIL));
            channel.send(Responses.getResponse(Responses.GUILDNOTSETUP));
        }
    }

    private async getRandomSquadronEmbed(guildId: string, channel: TextChannel, numberToSelect: number, categoryToSelect: string): Promise<MessageEmbed> {
        let guild = await this.db.model.guild.findOne({guild_id: guildId});
        if (guild) {
            let categories: CategoryChannel[] = []
            if (categoryToSelect === 'all') {
                guild.squadron_channel_category_id.forEach(categoryId => {
                    categories.push(channel.guild.channels.cache.get(categoryId) as CategoryChannel)
                })
            } else {
                let index = guild.squadron_channel_category_id.indexOf(categoryToSelect)
                if (index >= 0) {
                    categories.push(channel.guild.channels.cache.get(categoryToSelect) as CategoryChannel)
                } else {
                    const categoryToSelectObject = this.getChannelCategoryFromName(channel, categoryToSelect)
                    if (categoryToSelectObject) {
                        categories.push(categoryToSelectObject)
                    } else {
                        await channel.send(Responses.getResponse(Responses.FAIL));
                        channel.send(Responses.getResponse(Responses.IDNOTFOUND));
                        return
                    }
                }
            }
            if (categories.length === 0) {
                await channel.send(Responses.getResponse(Responses.FAIL));
                channel.send(Responses.getResponse(Responses.IDNOTFOUND));
                return
            }
            let channelsToSelect = channel.guild.channels.cache.filter(channel => categories.map(category => category.id).includes(channel.parentId)).random(numberToSelect);
            let embed = new MessageEmbed()
            embed.setTitle("Selected Squadrons")
            embed.setColor([255, 0, 255]);
            embed.setTimestamp(new Date());
            let idList = "";
            channelsToSelect.forEach(channel => {
                idList += `${channel.id} - #${channel.name}\n`;
            })
            embed.addField("Ids and Names", idList);
            return embed
        } else {
            await channel.send(Responses.getResponse(Responses.FAIL));
            channel.send(Responses.getResponse(Responses.GUILDNOTSETUP));
        }
    }

    private getChannelCategoryFromName(channel: TextChannel, categoryName: string, iteration?: number) {
        return channel.guild.channels.cache.find(channel => channel.name.toLowerCase() === `${categoryName.toLowerCase()} squadrons${iteration ? ` ${iteration}` : ``}`) as CategoryChannel
    }

    help(): [string, string, string, string[]] {
        return [
            'squadchannels(aliases: sqch)',
            'Performs operations on squadron channels',
            'squadchannels <get|random|create> <number> <all|channel category id|channel category name>',
            [
                '`@SRCBot squadchannels get 3 all`',
                '`@SRCBot squadchannels random 2 general`',
                '`@SRCBot squadchannels create pcps general my squadron`',
                '`@SRCBot sqch g 4 1234564789012345678`',
                '`@SRCBot squadchannels get 3 123456789012345678`'
            ]
        ];
    }
}
