/*
 * Copyright 2006-2007 Deutsches Forschungszentrum fuer Kuenstliche Intelligenz
 *
 * You may not use this file except under the terms of the accompanying license.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Project: BoNeSi
 * File: tcpoptions.h 
 * Purpose: support for the options field in the tcp header 
 * Responsible: Markus Goldstein
 * Primary Repository: https://github.com/Markus-Go/bonesi
 * Web Sites: madm.dfki.de, www.goldiges.de
 */

#ifndef TCPOPTIONS_H_
#define TCPOPTIONS_H_

#define NUM_TCP_OPTIONS 7

typedef struct{
    u_int8_t length;
    u_int8_t* options;
    float prob;
} TcpOption;

inline static void initTcpOptions(TcpOption tcpOptions[]) {
    tcpOptions[0].prob = 0.46f / 3.f;
    tcpOptions[0].length = 20;
    tcpOptions[0].options = (u_int8_t*)malloc(tcpOptions[0].length);
    memcpy(tcpOptions[0].options,
           "\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
           //   03 03 0a 01 02 04 01 09 08 0a
           //   3f 3f 3f 3f 00 00 00 00 00 00
           tcpOptions[0].length);
    
    tcpOptions[1].prob = 0.46f / 3.f;
    tcpOptions[1].length = 20;
    tcpOptions[1].options = (u_int8_t*)malloc(tcpOptions[1].length);
    memcpy(tcpOptions[1].options,
           "\002\004\005\264\001\003\003\000\001\001\010\012\000\165\012\042\000\000\000\000",
           //   02 04 05 b4 01 03 03 00 01 01
           //   08 0a 00 75 0a 22 00 00 00 00
           tcpOptions[1].length);
    
    tcpOptions[2].prob = 0.46f / 3.f;
    tcpOptions[2].length = 20;
    tcpOptions[2].options = (u_int8_t*)malloc(tcpOptions[2].length);
    memcpy(tcpOptions[2].options,
           "\002\004\005\226\004\002\010\012\155\264\137\256\000\000\000\000\001\003\003\000",
           //   02 04 05 96 04 02 08 0a 6d b4
           //   5f ae 00 00 00 00 01 03 03 00
           tcpOptions[2].length);
    
    tcpOptions[3].prob = 0.38f / 2.f;
    tcpOptions[3].length = 8;
    tcpOptions[3].options = (u_int8_t*)malloc(tcpOptions[3].length);
    memcpy(tcpOptions[3].options,
           "\002\004\005\354\001\004\002",
           //   02 04 04 ec 01 01 04 02
           tcpOptions[3].length);
    
    tcpOptions[4].prob = 0.38f / 2.f;
    tcpOptions[4].length = 8;
    tcpOptions[4].options = (u_int8_t*)malloc(tcpOptions[4].length);
    memcpy(tcpOptions[4].options,
           "\002\004\005\264\001\004\002",
           //   02 04 05 b4 01 01 04 02
           tcpOptions[4].length);
    
    tcpOptions[5].prob = 0.05f;
    tcpOptions[5].length = 12;
    tcpOptions[5].options = (u_int8_t*)malloc(tcpOptions[5].length);
    memcpy(tcpOptions[5].options,
           "\002\004\005\264\001\003\003\002\001\001\004\002",
           //   02 04 05 b4 01 03 03 02 01 01 04 02
           tcpOptions[5].length);
    
    tcpOptions[6].prob = 0.1f;
    tcpOptions[6].length = 24;
    tcpOptions[6].options = (u_int8_t*)malloc(tcpOptions[6].length);
    memcpy(tcpOptions[6].options,
           "\002\004\005\172\001\003\003\000\001\001\010\012\121\140\216\150\000\000\000\000\004\002\000\000",
            //  02 04 05 7a 01 03 03 00 01 01
            //  08 0a 51 60 8e 68 00 00 00 00 04 02 00 00
           tcpOptions[6].length);
}

static int randTcpOptionsIndex(TcpOption tcpOptions[]) {
    float tcpOptionsProb = rand() / (float)RAND_MAX;
    int tcpOptionsIndex;
    for(tcpOptionsIndex=0; tcpOptionsIndex<NUM_TCP_OPTIONS - 1; tcpOptionsIndex++) {
        tcpOptionsProb -= tcpOptions[tcpOptionsIndex].prob;
        if(tcpOptionsProb <= 0.f) {
            break;
        }
    }
    return tcpOptionsIndex;
}

#endif /*TCPOPTIONS_H_*/
