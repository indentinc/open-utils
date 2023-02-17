import { IncomingMessage } from 'http'
import { parse } from 'url'
import { ParsedRequest, Theme } from './types'

export function parseRequest(req: IncomingMessage) {
  console.log('HTTP ' + req.url)
  const { pathname, query } = parse((req.url || '/').replace(/&amp;/g, '&'), true)
  const { fontSize, images, widths, heights, theme = 'dark', md } = query || {}

  if (Array.isArray(fontSize)) {
    throw new Error('Expected a single fontSize')
  }
  if (Array.isArray(theme)) {
    throw new Error('Expected a single theme')
  }

  const arr = (pathname || '/').slice(1).split('.')
  let text = ''
  if (arr.length === 0) {
    text = ''
  } else if (arr.length === 1) {
    text = arr[0]
  } else {
    text = arr.join('.')
  }

  text = text.replace('.png', '')

  const parsedRequest: ParsedRequest = {
    fileType: 'png',
    text: decodeURIComponent(text),
    theme: theme === 'dark' ? 'dark' : 'light',
    md: md === '1' || md === 'true',
    fontSize: fontSize || '100px',
    images: getArray(images),
    widths: getArray(widths),
    heights: getArray(heights),
  }
  parsedRequest.images = getDefaultImages(
    parsedRequest.images,
    parsedRequest.theme
  )
  return parsedRequest
}

function getArray(stringOrArray: string[] | string | undefined): string[] {
  if (typeof stringOrArray === 'undefined') {
    return []
  } else if (Array.isArray(stringOrArray)) {
    return stringOrArray
  } else {
    return [stringOrArray]
  }
}

function getDefaultImages(images: string[], _theme: Theme): string[] {
  const defaultImage = 'https://indent.com/static/favicon.png'
  if (!images || !images[0]) {
    return [defaultImage]
  }
  if (
    !images[0].startsWith('https://assets.vercel.com/') &&
    !images[0].startsWith('https://assets.zeit.co/')
  ) {
    images[0] = defaultImage
  }
  return images
}
