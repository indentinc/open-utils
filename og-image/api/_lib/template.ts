import { readFileSync } from 'fs'
import { sanitizeHtml } from './sanitizer'
import { ParsedRequest } from './types'
const { marked } = require('marked')

const rglr = readFileSync(
  `${__dirname}/../_fonts/Inter-Regular.woff2`
).toString('base64')
const bold = readFileSync(`${__dirname}/../_fonts/Inter-Bold.woff2`).toString(
  'base64'
)
const medi = readFileSync(`${__dirname}/../_fonts/Inter-Medium.woff2`).toString(
  'base64'
)
const semi = readFileSync(`${__dirname}/../_fonts/Inter-Medium.woff2`).toString(
  'base64'
)
const darkBg = readFileSync(`${__dirname}/../images/bg.png`).toString('base64')
const lightBg = readFileSync(`${__dirname}/../images/bg-light.png`).toString('base64')

function getCss(theme: string, fontSize: string) {
  let foreground = 'white'

  if (theme === 'light') {
    foreground = 'black'
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
        font-family: 'Inter';
        font-style: normal;
        font-weight: 500;
        src: url(data:font/woff2;charset=utf-8;base64,${medi})  format("woff2");
      }
    
    @font-face {
        font-family: 'Inter';
        font-style: normal;
        font-weight: 600;
        src: url(data:font/woff2;charset=utf-8;base64,${semi})  format("woff2");
      }

    body {
        margin: 0;
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
        background: ${theme === 'light' ? '#fff;' : `#000;`}
        background-image: url(data:image/png;base64,${theme === 'light' ? lightBg : darkBg});
        background-size: 150% 150%;
        background-position: 50% 0;
    }

    .bg-mask {
        // position: absolute;
        // top: 0;
        // left: 0;
        // width: 100vw;
        // height: 100vh;
        // content: ' ';
        // background-image: linear-gradient(to bottom right, #fff 50%, rgba(256,256,256,0.25));
        // z-index: 2;
    }

    .container {
        position: relative;
        z-index: 10;
    }

    code {
        color: #D400FF;
        font-family: 'monospace';
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
        font-weight: 500;
        color: ${foreground};
        line-height: 1.45;
        transform: translateY(85px);
    }`
}

export function getHtml(parsedReq: ParsedRequest) {
  const {
    text,
    theme = 'dark',
    md,
    fontSize,
    images,
    widths,
    heights,
  } = parsedReq
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
            <div class="logo-wrapper">
                ${images
                  .map(
                    (img, i) =>
                      getPlusSign(i) + getImage(img, widths[i], heights[i])
                  )
                  .join('')}
            </div>
            <div class="spacer">
            <div class="heading">${md ? marked(text) : sanitizeHtml(text)}
            </div>
        </div>
    </body>
</html>`
}

function getImage(src: string, width = 'auto', height = '225') {
  return `<img
        class="logo"
        alt="Generated Image"
        src="${sanitizeHtml(src)}"
        width="${sanitizeHtml(width)}"
        height="${sanitizeHtml(height)}"
    />`
}

function getPlusSign(i: number) {
  return i === 0 ? '' : '<div class="plus">+</div>'
}
