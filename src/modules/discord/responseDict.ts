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

export class Responses {
    public static readonly SUCCESS = [
        "Your wish is my command!",
        "All done boss! :thumbsup:",
        "It is done! :ok_hand:"
    ];
    public static readonly FAIL = [
        "Um...sorry couldn't do that",
        "Computer says no",
        "Oops! problem... :frowning:",
        "Eeek! problems :frowning:"
    ];
    public static readonly NOPARAMS = [
        "Um...I think you are forgetting something",
        "I need more details to work on",
        "Yeah...go on!"
    ];
    public static readonly TOOMANYPARAMS = [
        "Aaah...thats too many details!",
        "No need to hurry. Give me the details one by one"
    ];
    public static readonly NOTACOMMAND = [
        "Um...were you trying to give me a command? If so you may be using the wrong one"
    ];
    public static readonly INSUFFICIENTPERMS = [
        "You don't have the permissions to make me do that"
    ];
    public static readonly IDNOTFOUND = [
        "The ID you entered does not exist"
    ];
    public static readonly GUILDNOTSETUP = [
        "Your guild has not been setup yet."
    ];
    public static readonly NOTATEXTCHANNEL = [
        "The entered channel is not a text channel. Please enter a text channel"
    ];
    public static readonly EMBEDPERMISSION = [
        "I don't have permissions to send a message and/or create an embed and/or attach files in the entered channel. Please assign the permissions to me."
    ];
    public static readonly CHANNELPERMISSIONS = [
        "I don't have permissions to manage channels. Please assign the permissions to me."
    ];
    public static readonly CHANNELEXISTS = [
        "A channel already exists for this squadron name and platform."
    ];

    public static getResponse(action: string[]): string {
        return action[Math.floor(Math.random() * action.length)];
    }
}
