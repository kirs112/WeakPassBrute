import { useState, useEffect } from "react";
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event'

// import { getVersion } from '@tauri-apps/api/app';
import "./App.css";



interface ServiceOption {
  id: string;
  name: string;
  checked: boolean;
}

interface BruteResult {
  id: number;
  ip: string;
  service: string;
  port: number;
  username: string;
  password: string;
  banner: string;
  time: string;
}

function App() {
  const [services, setServices] = useState<ServiceOption[]>([
    { id: "SSH", name: "SSH", checked: false },
    { id: "RDP", name: "RDP", checked: false },
    { id: "SMB", name: "SMB", checked: false },
    { id: "MySQL", name: "MySQL", checked: false },
    { id: "SQLServer", name: "SQLServer", checked: false },
    // { id: "Oracle", name: "Oracle", checked: false },
    { id: "FTP", name: "FTP", checked: false },
    { id: "MongoDB", name: "MongoDB", checked: false },
    // { id: "Memcached", name: "Memcached", checked: false },
    { id: "PostgreSQL", name: "PostgreSQL", checked: false },
    // { id: "Telnet", name: "Telnet", checked: false },
    // { id: "SMTP", name: "SMTP", checked: false },
    // { id: "VNC", name: "VNC", checked: false },
    { id: "Redis", name: "Redis", checked: false },
    { id: "Ms17010", name: "Ms17010", checked: false },
  ]);

  const [target, setTarget] = useState("");
  const [singleAccount, setSingleAccount] = useState(true);
  const [portCheck, setPortCheck] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [usernameSuffix, setUserNameSuffix] = useState("");
//  const [threads, setThreads] = useState(50);
  const [timeout, setTimeout] = useState(2);
  const [retries, setRetries] = useState(2);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<BruteResult[]>([

  ]);
  const [showAbout, setShowAbout] = useState(false);
  const [showUpdate, setShowUpdate] = useState(false);
  const [showFeedback, setShowFeedback] = useState(false);
  const [showProxy, setShowProxy] = useState(false);
  const [showPortSettings, setShowPortSettings] = useState(false);
  // const [activeProxyTab, setActiveProxyTab] = useState<'http' | 'socks5'>('http');
  const [proxyConfig, setProxyConfig] = useState({
    socks5: {
      enabled: false,
      host: '',
      port: '',
      username: '',
      password: ''
    }
  });
  const [updateStatus, setUpdateStatus] = useState<string>("检查中...");
  const [portSettings, setPortSettings] = useState([
    { id: 1, service: 'SSH', port: '22' },
    { id: 2, service: 'RDP', port: '3389' },
    { id: 3, service: 'SMB', port: '445' },
    { id: 4, service: 'MySQL', port: '3306' },
    { id: 5, service: 'SQLServer', port: '1433' },
    // { id: 6, service: 'Oracle', port: '1521' },
    { id: 7, service: 'FTP', port: '21' },
    { id: 8, service: 'MongoDB', port: '27017' },
    // { id: 9, service: 'Memcached', port: '11211' },
    { id: 10, service: 'PostgreSQL', port: '5432' },
    // { id: 11, service: 'Telnet', port: '23' },
    // { id: 12, service: 'VNC', port: '5900' },
    { id: 13, service: 'Redis', port: '6379' },
    { id: 14, service: 'Ms17010', port: '445' },
  ]);

  const [newService, setNewService] = useState('');
  const [newPort, setNewPort] = useState('');

  useEffect(() => {

    const unsubscribe = listen('port_check_result', (event) => {
      const message = event.payload as string;
      const timestamp = new Date().toLocaleTimeString();
      setLogs(prevLogs => {
        const newLogs = [...prevLogs, `[${timestamp}] ${message}`];
        return newLogs.slice(-50); // 减少为50条以提高性能
      });
    });
  
    // 清理函数
    return () => {
      unsubscribe.then(fn => fn());
    };
  }, []); // 空依赖数组确保效果只运行一次

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prevLogs => [...prevLogs, `[${timestamp}] ${message}`]);
  };

  const clearLogs = () => {
    setLogs([]);
  };


async function startBruteForce(bruteParams:any) {
    try {
      // 如果选择了Redis服务且没有用户名，设置一个空用户名
      if (bruteParams.selectedServices.includes("Redis") && !bruteParams.username) {
        bruteParams.username = "";
        addLog("Redis服务使用空用户名连接");
      }

      // 如果只选择了MS17010，设置空用户名和密码
      if (bruteParams.selectedServices.includes("Ms17010") && 
          bruteParams.selectedServices.length === 1) {
        bruteParams.username = "";
        bruteParams.password = "";
        addLog("MS17010扫描不需要用户名和密码");
      }
      
      // ✅ 这里要加 `await`
      const bruteResults = await invoke<BruteResult[]>("start_brute_force", bruteParams);
      
      if (Array.isArray(bruteResults)) {
        addLog(`爆破结果: ${JSON.stringify(bruteResults)}`);
        // setResults(bruteResults);
        setResults((prevResults) => [...prevResults, ...bruteResults]);
      } else {
        addLog(`${bruteResults}`);
        console.error("后端返回的格式错误:", bruteResults);
      }
    } catch (error) {
      addLog(`${error}`);
      console.error("爆破执行错误:", error);
    }
  }
  

  const handleServiceChange = (id: string) => {
    setServices(services.map(service =>
      service.id === id ? { ...service, checked: !service.checked } : service
    ));
    addLog(`服务 ${id} ${services.find(s => s.id === id)?.checked ? "取消选择" : "已选择"}`);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const selectedServices = services.filter(s => s.checked).map(s => s.name);
    // const selectedServicesStr = selectedServices.join(", ");
    // addLog(`选中的服务: ${selectedServicesStr || "无"}`);
    if (selectedServices.length==0) {
      addLog("未选择服务");
      return;
    }
    // addLog(`${selectedServices}`);

    addLog(`选中的服务: ${selectedServices}`);
    if (!target) {
      addLog("请设置目标地址");
      return;
    }

    // 检查是否选择了文件
    // 如果选择了Redis服务，则不需要用户名
    const hasNoUserPassService = selectedServices.includes("Redis") || selectedServices.includes("Ms17010");
    if (!username && !hasNoUserPassService) {
      addLog("请设置用户名");
      return;
    }
    if (!password && !hasNoUserPassService) {
      addLog("请设置密码");
      return;
    }

    // 收集所有需要传递给后端的数据
    const bruteParams = {
      target,
      singleAccount,
      portCheck,
      username,
      password,
      usernameSuffix,
      // threads,
      timeout,
      retries,
      selectedServices: selectedServices,
      proxyConfig,
      portSettings: portSettings
        .filter(setting => selectedServices.includes(setting.service))
        .reduce((acc, setting) => {
          acc[setting.service] = setting.port;
          return acc;
        }, {} as Record<string, string>)
    };

    startBruteForce(bruteParams);
    // addLog(`开始检查目标: ${target}`);
    
  };

  const handleStop = () => {
    addLog("停止检查");
    // 调用后端API停止爆破任务
    try {
      invoke('stop_brute_force')
        .then(() => {
          addLog('爆破任务已停止');
        })
        .catch((error) => {
          console.error('停止爆破任务错误:', error);
          addLog(`停止爆破任务失败: ${error instanceof Error ? error.message : String(error)}`);
        });
    } catch (error) {
      console.error('调用停止API错误:', error);
      addLog(`停止爆破任务失败: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const handleFileUpload = async (type: 'username' | 'password') => {
    // if (!isTauriReady) {
    //   addLog('Tauri 未准备就绪，请稍后再试');
    //   return;
    // }

    try {
      const selected = await open({
        multiple: false,
        directory: false,
        defaultPath: "",
        filters: [{
          name: 'Text Files',
          extensions: ['*']
        }]
      });
      
      if (!selected || selected.length === 0) {
        addLog('未选择文件');
        return;
      }

      const filePath = selected;

      if (type === 'username') {
          setUsername(filePath);
          addLog(`用户名文件已选择: ${filePath}`);
      } else {
          setPassword(filePath);
          addLog(`密码文件已选择: ${filePath}`);
      }
    } catch (error) {
      console.error('文件选择错误:', error);
      addLog(`文件选择失败: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const handleTargetFileUpload = async () => {

    try {
      const selected = await open({
        multiple: false,
        directory: false,
        defaultPath: "",
        filters: [{
          name: 'All Files',
          extensions: ['*']
        }]
      });
      
      if (!selected || selected.length === 0) {
        addLog('未选择文件');
        return;
      }

      const filePath = selected;
      setTarget(filePath);
      addLog(`目标IP文件已选择: ${filePath}`);
    } catch (error) {
      console.error('文件选择错误:', error);
      addLog(`文件选择失败: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const handleAboutClick = () => {
    setShowAbout(true);
  };

  const handleCloseAbout = () => {
    setShowAbout(false);
  };

  const checkForUpdates = async () => {
    setUpdateStatus("检查中...");
    try {
      const response = await fetch('https://github.com/kirs112/');
      if (response.ok) {
        setUpdateStatus("已是最新版本");
        addLog("检查更新完成");
      } else {
        setUpdateStatus("检查更新失败");
        addLog("检查更新失败:https://github.com/kirs112/WeakPassBrute");
      }
    } catch (error) {
      setUpdateStatus("检查更新失败");
      addLog(`检查更新失败: https://github.com/kirs112/WeakPassBrute ${error}`);
    }
  };

  const handleUpdateClick = () => {
    setShowUpdate(true);
    checkForUpdates();
  };

  const handleCloseUpdate = () => {
    setShowUpdate(false);
  };

  const handleFeedbackClick = () => {
    setShowFeedback(true);
  };

  const handleCloseFeedback = () => {
    setShowFeedback(false);
  };

  const handleProxyClick = () => {
    setShowProxy(true);
  };

  const handleCloseProxy = () => {
    setShowProxy(false);
  };

  // const handleProxyTabChange = (tab: 'http' | 'socks5') => {
  //   setActiveProxyTab(tab);
  // };

  const handleProxyConfigChange = (field: string, value: string | boolean) => {
    setProxyConfig(prev => ({
      socks5: {
        ...prev.socks5,
        [field]: value
      }
    }));
  };

  const handlePortSettingsClick = () => {
    setShowPortSettings(true);
  };

  const handleClosePortSettings = () => {
    setShowPortSettings(false);
  };

  const handlePortChange = (id: number, newPort: string) => {
    setPortSettings(prevSettings =>
      prevSettings.map(setting =>
        setting.id === id ? { ...setting, port: newPort } : setting
      )
    );
  };

  const handleSavePortSettings = () => {
    addLog("端口设置已保存");
    handleClosePortSettings();
  };

  const handleAddPort = () => {
    if (!newService || !newPort) {
      addLog("服务名称和端口号不能为空");
      return;
    }

    const newId = Math.max(...portSettings.map(s => s.id)) + 1;
    setPortSettings(prev => [...prev, {
      id: newId,
      service: newService,
      port: newPort
    }]);
    setNewService('');
    setNewPort('');
    addLog(`添加新端口配置：${newService}:${newPort}`);
  };

  // 添加一个计算属性来判断是否应该禁用用户名密码输入
  const shouldDisableCredentials = () => {
    const selectedServices = services.filter(s => s.checked).map(s => s.name);
    return selectedServices.length === 1 && selectedServices[0] === "Ms17010";
  };

  return (
    <div className="app-container">
      <div className="menu-bar">
        <div className="menu-item" onClick={handleProxyClick}>代理</div>
        <div className="menu-item" onClick={handlePortSettingsClick}>端口设置</div>
        <div className="menu-item">
          帮助
          <div className="dropdown-menu">
            <div className="dropdown-item" onClick={handleUpdateClick}>更新</div>
            <div className="dropdown-divider"></div>
            <div className="dropdown-item" onClick={handleFeedbackClick}>意见反馈</div>
            <div className="dropdown-divider"></div>
            <div className="dropdown-item">版本 1.0.0</div>
          </div>
        </div>
        <div className="menu-item" onClick={handleAboutClick}>关于</div>
      </div>
      <div className="main-wrapper">
        <div className="service-selection">
          {services.map(service => (
            <div key={service.id} className="service-item">
              <input
                type="checkbox"
                id={service.id}
                checked={service.checked}
                onChange={() => handleServiceChange(service.id)}
              />
              <label htmlFor={service.id}>{service.name}</label>
            </div>
          ))}
        </div>

        <div className="main-content">
          <div className="config-section">
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>目标：</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="127.0.0.1 or 127.0.0.1:3389"
                />
                <button
                  type="button"
                  onClick={handleTargetFileUpload}
                  className="file-upload-button"
                >
                  选择文件
                </button>
                <div className="checkbox">
                  <input
                    type="checkbox"
                    id="singleAccount"
                    checked={singleAccount}
                    onChange={(e) => setSingleAccount(e.target.checked)}
                  />
                  <label htmlFor="singleAccount">只检查一个账户</label>
                </div>
              </div>
              <div className="form-group">
                <label>账户：</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={shouldDisableCredentials()}
                  placeholder={shouldDisableCredentials() ? "MS17010不需要凭据" : "请输入用户名"}
                />
                <button
                  type="button"
                  onClick={() => handleFileUpload('username')}
                  className="file-upload-button"
                  disabled={shouldDisableCredentials()}
                >
                  选择文件
                </button>
                <div className="checkbox">
                  <input
                    type="checkbox"
                    id="portCheck"
                    checked={portCheck}
                    onChange={(e) => setPortCheck(e.target.checked)}
                  />
                  <label htmlFor="portCheck">检测端口状态</label>
                </div>
              </div>

              <div className="form-group">
                <label>密码：</label>
                <input
                  type="text"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={shouldDisableCredentials()}
                  placeholder={shouldDisableCredentials() ? "MS17010不需要凭据" : "请输入密码"}
                />
                <button
                  type="button"
                  onClick={() => handleFileUpload('password')}
                  className="file-upload-button"
                  disabled={shouldDisableCredentials()}
                >
                  选择文件
                </button>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>域名：</label>
                  <input
                    type="text"
                    value={usernameSuffix}
                    onChange={(e) => setUserNameSuffix(e.target.value)}
                    placeholder="@attack.com"
                    className="password-suffix-input"
                  />
                </div>

                <div className="form-group">
                  <label>超时：</label>
                  <select value={timeout} onChange={(e) => setTimeout(Number(e.target.value))}>
                    {[2,5, 10, 15, 20, 25, 30].map(num => (
                      <option key={num} value={num}>{num}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label>重试：</label>
                  <select value={retries} onChange={(e) => setRetries(Number(e.target.value))}>
                    {[0, 1, 2, 3, 4, 5].map(num => (
                      <option key={num} value={num}>{num}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="button-group">
                <button type="submit">开始检查</button>
                <button type="button" onClick={handleStop}>停止检查</button>
              </div>
            </form>
          </div>

          <div className="results-section">
            <div className="results-header">
              <label>结果</label>
            </div>
            <div className="results-table">
              <table>
                <thead>
                  <tr>
                    <th>序号</th>
                    <th>IP地址</th>
                    <th>服务</th>
                    <th>端口</th>
                    <th>账户名</th>
                    <th>密码</th>
                    <th>BANNER</th>
                    <th>用时[毫秒]</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((result) => (
                    <tr key={result.id}>
                      <td>{result.id}</td>
                      <td>{result.ip}</td>
                      <td>{result.service}</td>
                      <td>{result.port}</td>
                      <td>{result.username}</td>
                      <td>{result.password}</td>
                      <td>{result.banner}</td>
                      <td>{result.time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="log-section">
            <div className="log-header">
              <h3>日志</h3>
              <button onClick={clearLogs}>清空日志</button>
            </div>
            <div className="log-content">
              {logs.map((log, index) => (
                <div key={index}>{log}</div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {showUpdate && (
        <div className="modal-overlay" onClick={handleCloseUpdate}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">更新</h2>
              <button className="modal-close" onClick={handleCloseUpdate}>×</button>
            </div>
            <div className="modal-content">
              <p>当前版本：1.0.0</p>
              <p>{updateStatus}</p>
            </div>
          </div>
        </div>
      )}

      {showPortSettings && (
        <div className="modal-overlay" onClick={handleClosePortSettings}>
          <div className="modal port-settings-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">端口设置</h2>
              <button className="modal-close" onClick={handleClosePortSettings}>×</button>
            </div>
            <div className="modal-content">
              <div className="port-settings-table">
                <table>
                  <thead>
                    <tr>
                      <th>序号</th>
                      <th>服务</th>
                      <th>端口</th>
                    </tr>
                  </thead>
                  <tbody>
                    {portSettings.map(setting => (
                      <tr key={setting.id}>
                        <td>{setting.id}</td>
                        <td>{setting.service}</td>
                        <td>
                          <input
                            type="text"
                            value={setting.port}
                            onChange={(e) => handlePortChange(setting.id, e.target.value)}
                            className="port-input"
                          />
                        </td>
                      </tr>
                    ))}
                    <tr>
                      <td>新增</td>
                      <td>
                        <input
                          type="text"
                          value={newService}
                          onChange={(e) => setNewService(e.target.value)}
                          placeholder="输入服务名称"
                          className="port-input"
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          value={newPort}
                          onChange={(e) => setNewPort(e.target.value)}
                          placeholder="输入端口号"
                          className="port-input"
                        />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="port-settings-actions">
                <button className="add-port-button" onClick={handleAddPort}>新增加端口</button>
                <button className="save-button" onClick={handleSavePortSettings}>保存</button>
              </div>
            </div>
          </div>
        </div>
      )}

{showProxy && (
  <div className="modal-overlay" onClick={handleCloseProxy}>
    <div className="modal" onClick={e => e.stopPropagation()}>
      <div className="modal-header">
        <h2 className="modal-title">代理设置</h2>
        <button className="modal-close" onClick={handleCloseProxy}>×</button>
      </div>
      <div className="modal-content">
        <div className="proxy-form">
          <div className="form-group">
            <div className="checkbox-group">
              <input
                type="checkbox"
                id="socks5-enabled"
                checked={proxyConfig.socks5.enabled}
                onChange={(e) => handleProxyConfigChange('enabled', e.target.checked)}
              />
              <label htmlFor="socks5-enabled">
                启用SOCKS5代理
              </label>
            </div>
          </div>
          
          <div className="form-group">
            <label htmlFor="socks5-host">主机地址：</label>
            <input
              type="text"
              id="socks5-host"
              value={proxyConfig.socks5.host}
              onChange={(e) => handleProxyConfigChange('host', e.target.value)}
              placeholder="例如：127.0.0.1"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="socks5-port">端口：</label>
            <input
              type="text"
              id="socks5-port"
              value={proxyConfig.socks5.port}
              onChange={(e) => handleProxyConfigChange('port', e.target.value)}
              placeholder="例如：1080"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="socks5-username">用户名：</label>
            <input
              type="text"
              id="socks5-username"
              value={proxyConfig.socks5.username}
              onChange={(e) => handleProxyConfigChange('username', e.target.value)}
              placeholder="可选"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="socks5-password">密码：</label>
            <input
              type="password"
              id="socks5-password"
              value={proxyConfig.socks5.password}
              onChange={(e) => handleProxyConfigChange('password', e.target.value)}
              placeholder="可选"
            />
          </div>
        </div>
        
        <div className="proxy-actions">
          <button 
            className="save-button"
            onClick={() => {
              addLog(`SOCKS5代理配置已保存`);
              handleCloseProxy();
            }}
          >
            保存
          </button>
        </div>
      </div>
    </div>
  </div>
)}

      {showFeedback && (
        <div className="modal-overlay" onClick={handleCloseFeedback}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">意见反馈</h2>
              <button className="modal-close" onClick={handleCloseFeedback}>×</button>
            </div>
            <div className="modal-content">
              <p>如果您在使用过程中遇到问题或有任何建议，请发送邮件至：</p>
              <p style={{ textAlign: 'center', fontSize: '16px', margin: '20px 0', color: '#1890ff' }}>
                kirs_gu@sina.com
              </p>
              <p>感谢您的支持！</p>
            </div>
          </div>
        </div>
      )}

      {showAbout && (
        <div className="modal-overlay" onClick={handleCloseAbout}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">关于</h2>
              <button className="modal-close" onClick={handleCloseAbout}>×</button>
            </div>
            <div className="modal-content">
              <p>此工具为弱口令服务端口检查工具，提供给企业、运维人员、安全工程师用于企业内部弱口令检查使用。</p>
              <p>支持的服务：SSH、RDP、SMB、MySQL、SQLServer、Oracle、FTP、MongoDB、Memcached、PostgreSQL、Telnet、SMTP、VNC、Redis</p>
              <div className="disclaimer">
                请勿非法使用！
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;


