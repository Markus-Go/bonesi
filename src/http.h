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
 * File: http.h 
 * Purpose: support for HTTP-GET attacks 
 * Responsible: Markus Goldstein
 * Primary Repository: https://github.com/Markus-Go/bonesi
 * Web Sites: madm.dfki.de, www.goldiges.de
 */


#ifndef HTTP_H_
#define HTTP_H_

#include <stdio.h>
ssize_t getline(char **lineptr, size_t *n, FILE *stream);

#define URL_SIZE 4096 
static const int USERAGENT_SIZE = 150;

typedef struct{
    char protocol[50];
    char host[2000];
    char path[2000];
    //char url[URL_SIZE];
} Url;

typedef struct{
    int size;
    Url* urls;
} Url_array;


/**
 * reads a single url from a given text file
 * @return the url
 */
Url getURL(FILE *file){
    char buffer[URL_SIZE];
    Url u;
    u.host[0] = '\0';
    u.path[0] = '\0';
    u.protocol [0] = '\0';
    int r = fscanf(file, "%4096s\n", buffer);
    if(sscanf(buffer,"%50[^:/]://%2000[^/]/%2000s", u.protocol, u.host, u.path) != 3) {
        u.path[0] = '\0';
    }
    //sprintf(u.url, "%s/%s",u.host,u.path);
    return u;
}

/**
 * reads urls from a text file and stores them in an array
 */
Url_array readURLs(const char* urlfilename, int verbose){
    FILE *file;
    Url* urllist;
    if ((file = fopen(urlfilename, "r")) == NULL) {
        fprintf(stderr,"File %s could not be opened.\n", urlfilename);
        exit(EXIT_FAILURE);
    }
    printf("reading urls file... ");
    fflush(stdout);
    int url_count = 0; 
    char buffer[URL_SIZE];
    while(!feof(file)){
        int r = fscanf(file, "%4096s\n", buffer);
        if(strlen(buffer) > 4)   // > 4 'cause there are at least 4 characters in our template
            url_count++;
    }
    rewind(file);
    urllist = malloc(url_count*sizeof(Url));
    int i = 0;
    while(!feof(file)){
        Url u = getURL(file) ;
        if(u.path[0] != '\0') {
            urllist[i] = u;
            i++;
        }
    }
    fclose(file);
    printf("done\n");
    if(verbose) {
        printf("The URLs are: \n");
        int j;
        for(j=0; j<url_count; j++){
            printf("%s/%s\n",urllist[j].host,urllist[j].path);
        }
    }
    Url_array url_arr;
    url_arr.size = url_count;
    url_arr.urls = urllist;
    return url_arr;
}

/**
 * This function builds a http request 
 * @param nurl number of url in urllist
 * @param nref number of referer in urllist
 * @param nuseragent number of useragent 
 */
void buildRequest(char request[], int nurl, int nref, int nuseragent, Url_array urls, char** useragents){
    //printf("buildRequest\n");
    char* host = urls.urls[nurl].host;
    char* path = urls.urls[nurl].path;
    char referer[500];
    char* useragent = useragents[nuseragent];
    
    sprintf(request,"GET /%s HTTP/1.0\r\nHost: %s\r\nUser-agent: %s\r\n",path, host, useragent);
    strcat(request,"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n");
    strcat(request,"Accept-Language: en-us,en;q=0.5\r\n");
    strcat(request,"Accept-Encoding: gzip,deflate\r\n");
    strcat(request,"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n");
    if(nref>=0){        
        strcat(request,"Connection: close\r\n");
        sprintf(referer,"Referer: %s/%s\r\n\r\n",urls.urls[nref].host,urls.urls[nref].path);
        strcat(request,referer);
    }
    else{
        strcat(request,"Connection: close\r\n\r\n");
    }
}

/**
 * reads the user agents from a text file and stores them in an array
 */
int readUserAgents(char*** useragents, const char* useragentfilename){
    FILE *file;
    char* buffer;
    if ( (file = fopen(useragentfilename, "r")) == NULL) {
        fprintf(stderr,"File %s could not be opened.\n", useragentfilename);
        exit(EXIT_FAILURE);
    }
    printf("reading user agents file...");
    fflush(stdout);
    int count = 0;
    size_t len = 0;
    ssize_t read;
    while((read = getline(&buffer,&len,file))!=-1) {
        count++;
    }
    rewind(file);
    *useragents = (char**)malloc(sizeof(char*)*count);
    count = 0;
    fflush(stdout);
    while((read = getline(&buffer,&len,file))!=-1) {
        buffer[strlen(buffer)-1] = '\0';
        (*useragents)[count] = (char*)malloc(USERAGENT_SIZE);
        strcpy((*useragents)[count],buffer);
        count++;
    }
    fclose(file);
    printf("done\n");
    return count;
}

#endif /*HTTP_H_*/
