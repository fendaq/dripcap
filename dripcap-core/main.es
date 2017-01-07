import { app, BrowserWindow } from 'electron';
import minimist from 'minimist';
import paperfilter from 'paperfilter';

if (require('electron-squirrel-startup')) app.quit();

if (!paperfilter.Session.permission) {
  if (process.platform === 'darwin') {
    require('dripcap-helper')();
  }
}

app.commandLine.appendSwitch('js-flags', '--harmony-async-await --no-memory-reducer');
app.commandLine.appendSwitch('--enable-experimental-web-platform-features');

app.on('quit', () => {

});

app.on('window-all-closed', () => app.quit());

app.on('ready', () => {
  let options = {
    width: 1200,
    height: 600,
    show: false,
    vibrancy: 'light',
    titleBarStyle: 'hidden-inset'
  };

  let argv = JSON.stringify(minimist(process.argv.slice(2)));

  let mainWindow = new BrowserWindow(options);
  mainWindow.loadURL(`file://${__dirname}/layout.htm`);
  mainWindow.webContents.on('crashed', () => mainWindow.reload());
  mainWindow.webContents.on('unresponsive', () => mainWindow.reload());
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.executeJavaScript(`require("./dripcap")(${argv}, "default")`, false).then(() => {
      mainWindow.show();
    });
  });
});
