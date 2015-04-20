<html>
<head>
<title>Yubikey example - Login</title>
</head>
<body>
	<h1>Login</h1>
	<p>
	<form action="login.jsp" method="POST">
		<table>
			<tr>
				<td><label for="email">E-mail:</label></td>
				<td><input name="email" type="text"></td>
			</tr>
			<tr>
				<td><label for="password">Password:</label></td>
				<td><input name="password" type="password" value=""></td>
			</tr>
			<tr>
				<td><label for="otp">OTP:</label></td>
				<td><input name="otp" type="password" value=""></td>
			</tr>
			<tr>
				<td colspan="2"><input type="submit" value="Login"></td>
			</tr>
			<%
			  if (request.getAttribute("message") != null) {
			%>
			<tr>
				<td colspan="2">${message}</td>
			</tr>
			<%
			  }
			%>
		</table>
	</form>
</body>
</html>