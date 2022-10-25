export type Tabs = {
  [x: string]: string
}

const playgroundTabs: Tabs = {
  indentBlog: `<div
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
    fontFamily: 'system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol"',
    color: 'white'
  }}
>
<div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
  background: '#000', opacity: 0.45
  }} />
  <img src="https://indent.com/static/favicon.png" style={{ width: 200, position: 'relative'}} />
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginTop: 40, maxWidth: 800, textAlign: 'center', position: 'relative' }}>
    Indent for Vercel: Temporary Access Roles
  </div>
</div>`
}

export default playgroundTabs
