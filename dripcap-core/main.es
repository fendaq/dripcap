import { app, BrowserWindow, dialog, shell } from 'electron';
import minimist from 'minimist';
import paperfilter from 'paperfilter';

if (require('electron-squirrel-startup')) app.quit();

if (!paperfilter.Session.permission && process.platform === 'darwin') {
  require('dripcap-helper')();
}

app.commandLine.appendSwitch('js-flags', '--harmony-async-await --no-memory-reducer');
app.commandLine.appendSwitch('--enable-experimental-web-platform-features');

app.on('quit', () => {

});

app.on('window-all-closed', () => app.quit());

app.on('ready', () => {
  if (process.platform === 'win32' && process.env['DRIPCAP_UI_TEST'] == null) {
    if (!paperfilter.Session.permission) {
      let button = dialog.showMessageBox({
        title: "WinPcap required",
        message: "Dripcap depends on WinPcap.\nPlease install WinPcap on your system.",
        buttons: ["Download WinPcap", "Quit"]
      });
      if (button === 0) {
        shell.openExternal('https://www.winpcap.org/install/');
      }
      app.quit();
    }
  }

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
