import { ImageResponse } from '@vercel/og'
import { NextRequest } from 'next/server'
import { marked } from 'marked'

export const config = {
  runtime: 'experimental-edge',
}

export async function loadFont(font: string) {
  const url = new URL('../../public/' + font, import.meta.url)
  return fetch(url).then((res) =>
    res.arrayBuffer()
  ).catch((err) => {
    console.error(err.cause)
    throw err
  })
}

export default async function handler(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)

    // ?title=<title>
    const hasTitle = searchParams.has('title')
    const title = hasTitle
      ? searchParams.get('title') || ''
      : 'Indent for Example:<br />Time-bound Access'

    const mdHtml = await marked.parse(title, { async: true })

    const [font, fontBold, fontIcon] = await Promise.all([
      loadFont('inter-latin-ext-400-normal.woff'),
      loadFont('inter-latin-ext-700-normal.woff'),
      loadFont('material-icons-base-400-normal.woff'),
    ])

    const fonts = [
      {
        name: 'Inter',
        data: font,
        weight: 400,
        style: 'normal',
      },
      {
        name: 'Inter',
        data: fontBold,
        weight: 700,
        style: 'normal',
      },
      {
        name: 'Material Icons',
        data: fontIcon,
        weight: 400,
        style: 'normal',
      },
    ]

    return new ImageResponse(
      (
        <div
          style={{
            height: '100%',
            width: '100%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            background: '#000',
            backgroundImage: 'url(https://i.imgur.com/BBBITAS.png)',
            backgroundSize: '110% 130%',
            backgroundPosition: '-5% 0',
            fontSize: 60,
            lineHeight: 1.35,
            fontWeight: 600,
            fontFamily: 'Times New Roman',
            color: 'white',
          }}
        >
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: '100%',
              height: '100%',
              background: '#000',
              opacity: 0.45,
            }}
          />
          <img
            src="https://indent.com/static/favicon.png"
            style={{ width: 200, position: 'relative' }}
          />
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              marginTop: 40,
              maxWidth: 800,
              textAlign: 'center',
              position: 'relative',
            }}
            // dangerouslySetInnerHTML={{ __html: mdHtml }}
          >
          </div>
          {mdHtml}
        </div>
      ),
      {
        width: 1200,
        height: 630,
        fonts: fonts,
      }
    )
  } catch (e: any) {
    console.log(`${e.message}`)
    return new Response(`Failed to generate the image`, {
      status: 500,
    })
  }
}
