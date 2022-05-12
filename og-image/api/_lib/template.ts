
import { readFileSync } from 'fs';
import { sanitizeHtml } from './sanitizer';
import { ParsedRequest } from './types';
const marked = require('marked');
const twemoji = require('twemoji');
const twOptions = { folder: 'svg', ext: '.svg' };
const emojify = (text: string) => twemoji.parse(text, twOptions);

const rglr = readFileSync(`${__dirname}/../_fonts/Inter-Regular.woff2`).toString('base64');
const bold = readFileSync(`${__dirname}/../_fonts/Inter-Bold.woff2`).toString('base64');
const mono = readFileSync(`${__dirname}/../_fonts/Vera-Mono.woff2`).toString('base64');

function getCss(theme: string, fontSize: string) {
    let foreground = 'black';

    if (theme === 'dark') {
        foreground = 'white';
    }

    return `
    @font-face {
        font-family: 'Inter';
        font-style:  normal;
        font-weight: normal;
        src: url(data:font/woff2;charset=utf-8;base64,${rglr}) format('woff2');
    }

    @font-face {
        font-family: 'Inter';
        font-style:  normal;
        font-weight: bold;
        src: url(data:font/woff2;charset=utf-8;base64,${bold}) format('woff2');
    }

    @font-face {
        font-family: 'Vera';
        font-style: normal;
        font-weight: normal;
        src: url(data:font/woff2;charset=utf-8;base64,${mono})  format("woff2");
      }

    body {
        position: relative;
        height: 100vh;
        display: flex;
        text-align: center;
        align-items: center;
        justify-content: center;
    }


    .bg-pattern {
        position: absolute;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        content: ' ';
        background: #49a2fe;
        /* background-size: 200px 200px; */
        /* background-image: linear-gradient(45deg, #000, #000 0.5%, #ffd700 0.5%, #ffd700 7.6%, #000 7.6%, #000 8.642857143%, #ff8c00 8.642857143%, #ff8c00 15.64285714%, #000 15.64285714%, #000 16.88571429%, #dc143c 16.88571429%, #dc143c 23.84285714%, #000 23.84285714%, #000 25%, transparent 25%), linear-gradient(-45deg, #000, #000 0.5%, #ffd700 0.5%, #ffd700 7.6%, #000 7.6%, #000 8.642857143%, #ff8c00 8.642857143%, #ff8c00 15.64285714%, #000 15.64285714%, #000 16.88571429%, #dc143c 16.88571429%, #dc143c 23.84285714%, #000 23.84285714%, #000 25%, transparent 25%), linear-gradient(45deg, transparent 73.85714286%, #000 73.85714286%, #000 75%, transparent 75%), linear-gradient(-45deg, transparent 73.85714286%, #000 73.85714286%, #000 75%, transparent 75%), linear-gradient(45deg, transparent 66.85714286%, #dc143c 66.85714286%, #dc143c 73.85714286%, transparent 73.85714286%), linear-gradient(-45deg, transparent 66.85714286%, #dc143c 66.85714286%, #dc143c 73.85714286%, transparent 73.85714286%), linear-gradient(45deg, transparent 65.71428571%, #000 65.71428571%, #000 66.85714286%, transparent 66.85714286%), linear-gradient(-45deg, transparent 65.71428571%, #000 65.71428571%, #000 66.85714286%, transparent 66.85714286%), linear-gradient(45deg, transparent 58.71428571%, #ff8c00 58.71428571%, #ff8c00 65.71428571%, transparent 65.71428571%), linear-gradient(-45deg, transparent 58.71428571%, #ff8c00 58.71428571%, #ff8c00 65.71428571%, transparent 65.71428571%), linear-gradient(45deg, transparent 57.57142857%, #000 57.57142857%, #000 58.71428571%, transparent 58.71428571%), linear-gradient(-45deg, transparent 57.57142857%, #000 57.57142857%, #000 58.71428571%, transparent 58.71428571%), linear-gradient(45deg, transparent 50.57142857%, #ffd700 50.57142857%, #ffd700 57.57142857%, transparent 57.57142857%), linear-gradient(-45deg, transparent 50.57142857%, #ffd700 50.57142857%, #ffd700 57.57142857%, transparent 57.57142857%), linear-gradient(45deg, transparent 49.42857143%, #000 49.42857143%, #000 50.57142857%, transparent 50.57142857%), linear-gradient(-45deg, transparent 49.42857143%, #000 49.42857143%, #000 50.57142857%, transparent 50.57142857%), linear-gradient(45deg, transparent 42.42857143%, #228b22 42.42857143%, #228b22 49.42857143%, transparent 49.42857143%), linear-gradient(-45deg, transparent 42.42857143%, #228b22 42.42857143%, #228b22 49.42857143%, transparent 49.42857143%), linear-gradient(45deg, transparent 41.28571429%, #000 41.28571429%, #000 42.42857143%, transparent 42.42857143%), linear-gradient(-45deg, transparent 41.28571429%, #000 41.28571429%, #000 42.42857143%, transparent 42.42857143%), linear-gradient(45deg, transparent 34.28571429%, #4169e1 34.28571429%, #4169e1 41.28571429%, transparent 41.28571429%), linear-gradient(-45deg, transparent 34.28571429%, #4169e1 34.28571429%, #4169e1 41.28571429%, transparent 41.28571429%), linear-gradient(45deg, transparent 33.142857143%, #000 33.142857143%, #000 34.28571429%, transparent 34.28571429%), linear-gradient(-45deg, transparent 33.142857143%, #000 33.142857143%, #000 34.28571429%, transparent 34.28571429%); */
        background-image: linear-gradient(to bottom right, #fff 50%,rgba(0,0,0,0)), url('data:image/svg+xml,%3Csvg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"%3E%3Cpath d="M8 16c4.418 0 8-3.582 8-8s-3.582-8-8-8-8 3.582-8 8 3.582 8 8 8zm0-2c3.314 0 6-2.686 6-6s-2.686-6-6-6-6 2.686-6 6 2.686 6 6 6zm33.414-6l5.95-5.95L45.95.636 40 6.586 34.05.636 32.636 2.05 38.586 8l-5.95 5.95 1.414 1.414L40 9.414l5.95 5.95 1.414-1.414L41.414 8zM40 48c4.418 0 8-3.582 8-8s-3.582-8-8-8-8 3.582-8 8 3.582 8 8 8zm0-2c3.314 0 6-2.686 6-6s-2.686-6-6-6-6 2.686-6 6 2.686 6 6 6zM9.414 40l5.95-5.95-1.414-1.414L8 38.586l-5.95-5.95L.636 34.05 6.586 40l-5.95 5.95 1.414 1.414L8 41.414l5.95 5.95 1.414-1.414L9.414 40z" fill="white" fill-opacity="1" fill-rule="evenodd"/%3E%3C/svg%3E');
    }

    .bg-mask {
        position: absolute;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        content: ' ';
        background-image: linear-gradient(to bottom right, #fff 50%, rgba(256,256,256,0.25));
        z-index: 2;
    }

    .container {
        position: relative;
        z-index: 10;
    }

    code {
        color: #D400FF;
        font-family: 'Vera';
        white-space: pre-wrap;
        letter-spacing: -5px;
    }

    code:before, code:after {
        content: '\`';
    }

    .logo-wrapper {
        display: flex;
        align-items: center;
        align-content: center;
        justify-content: center;
        justify-items: center;
    }

    .logo {
        margin: 0 75px;
    }

    .plus {
        color: #BBB;
        font-family: Times New Roman, Verdana;
        font-size: 100px;
    }

    .spacer {
        margin: 150px;
    }

    .emoji {
        height: 1em;
        width: 1em;
        margin: 0 .05em 0 .1em;
        vertical-align: -0.1em;
    }
    
    .heading {
        font-family: 'Inter', sans-serif;
        font-size: ${sanitizeHtml(fontSize)};
        font-style: normal;
        color: ${foreground};
        line-height: 1.8;
    }`;
}

export function getHtml(parsedReq: ParsedRequest) {
    const { text, theme, md, fontSize, images, widths, heights } = parsedReq;
    return `<!DOCTYPE html>
<html>
    <meta charset="utf-8">
    <title>Generated Image</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        ${getCss(theme, fontSize)}
    </style>
    <body>
        <div class="bg-pattern"></div>
        <div class="bg-mask"></div>
        <div class="container">
            <div class="spacer">
            <div class="logo-wrapper">
                ${images.map((img, i) =>
                    getPlusSign(i) + getImage(img, widths[i], heights[i])
                ).join('')}
            </div>
            <div class="spacer">
            <div class="heading">${emojify(
                md ? marked(text) : sanitizeHtml(text)
            )}
            </div>
        </div>
    </body>
</html>`;
}

function getImage(src: string, width ='auto', height = '225') {
    return `<img
        class="logo"
        alt="Generated Image"
        src="${sanitizeHtml(src)}"
        width="${sanitizeHtml(width)}"
        height="${sanitizeHtml(height)}"
    />`
}

function getPlusSign(i: number) {
    return i === 0 ? '' : '<div class="plus">+</div>';
}
