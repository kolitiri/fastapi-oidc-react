import React, { Component } from 'react';


class App extends Component {

  state = {
    producerLoginRedirectEndpoint: 'http://localhost:8000/login-redirect',
    producerLoginEndpoint: 'http://localhost:8000/login/',
    producerLogoutEndpoint: 'http://localhost:8000/logout/',
    producerLoginCheckEndpoint: 'http://localhost:8000/user-session-status/',
    userLoggedIn: false,
    userName: null,
  }

  componentDidMount() {
    this.authenticate()
  }

  setCookie = (cname, cvalue, exdays) => {
    var d = new Date();
    d.setTime(d.getTime() + (exdays*24*60*60*1000));
    var expires = "expires="+ d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
  }

  getCookie = (cname) => {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i <ca.length; i++) {
      var c = ca[i];
      while (c.charAt(0) === ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) === 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  }

  authenticate = () => {
    var authToken = (window.location.search.match(/authToken=([^&]+)/) || [])[1]
    window.history.pushState('object', document.title, "/");

    if (authToken) {
      // Try to get an access token from the server
      this.getAccessToken(authToken)
    } else {
      // Check user is logged in
      this.checkUserSessionStatus()
    }
  }

  getAccessToken = (authToken) => {
    const request = {
      method: 'GET',
      headers: {
        "Authorization": "Bearer " + authToken
      },
      credentials: 'include'
    }

    fetch(this.state.producerLoginEndpoint, request)
    .then(response => {
      // Check user is logged in
      this.checkUserSessionStatus()
    })
    .then(data => {})
    .catch(err => {})
  }

  checkUserSessionStatus = () => {
    const request = {
      method: 'GET',
      credentials: 'include'
    }

    fetch(this.state.producerLoginCheckEndpoint, request)
    .then(response => response.json())
    .then(data => {
      this.setState({
        userLoggedIn: data['userLoggedIn'],
        userName: data['userName'],
      })
    })
    .catch(err => {})
  }

  logout = () => {
    const request = {
      method: 'GET',
      credentials: 'include'
    }

    fetch(this.state.producerLogoutEndpoint, request)
    .then(response => response.json())
    .then(data => {window.location.reload()})
    .catch(err => {})
  }

  render() {
    return (
      <section id="page-container">
        {this.state.userLoggedIn ?
          <div>
            <div>
              You are now logged in!
            </div>
            <div>
              <button onClick={this.logout}>Logout</button>
            </div>
          </div> :
          <Login producerLoginRedirectEndpoint={this.state.producerLoginRedirectEndpoint}/>
        }
      </section>
    );
  }
}


function Login(props) {
  const googleLogin = () => {
    var auth_provider = "google-oidc"
    var login_url = props.producerLoginRedirectEndpoint + "?auth_provider=" + auth_provider
    window.location.href = login_url
  }

  const azureLogin = () => {
    var auth_provider = "azure-oidc"
    var login_url = props.producerLoginRedirectEndpoint + "?auth_provider=" + auth_provider
    window.location.href = login_url
  }

  return (
    <section>
      <div>
        <button onClick={googleLogin}>Login with Google</button>
      </div>
      <div>
        <button onClick={azureLogin}>Login with Microsoft</button>
      </div>
    </section>
  );
}

export default App;