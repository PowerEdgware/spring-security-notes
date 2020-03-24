
### Spring Security Reference
> 5.2.1.RELEASE  
> 三种方式：uses Spring Boot, Java Configuration,or XML Configuration.

**Spring Boot with Maven 基本使用**    

```
<properties>
<spring-security.version>5.2.1.RELEASE</spring-security.version>
</properties>
<dependencies>
	<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
	</dependency>
</dependencies>
```

** Maven Without Spring Boot**   

```
<dependencyManagement>
	<dependencies>
	<!-- ... other dependency elements ... -->
		<dependency>
		<groupId>org.springframework.security</groupId>
		<artifactId>spring-security-bom</artifactId>
		<version>5.2.1.RELEASE</version>
		<type>pom</type>
		<scope>import</scope>
		</dependency>
	</dependencies>
</dependencyManagement>

<dependencies>
	<!-- ... other dependency elements ... -->
	<dependency>
	<groupId>org.springframework.security</groupId>
	<artifactId>spring-security-web</artifactId>
	</dependency>
	<dependency>
	<groupId>org.springframework.security</groupId>
	<artifactId>spring-security-config</artifactId>
	</dependency>
</dependencies>
```

####  Architecture and Implementation 

> authentication 认证 ：登入  
> Authorization 授权 ：access-control   
>Java Authentication 
and Authorization Service (JAAS)

** 核心类和接口 **  

1.`SecurityContextHolder`  
用来存储和获取：`SecurityContext`   
默认使用`ThreadLocal`存储用户认证信息。存储对象`SecurityContext` 
内部包含`Authentication`用户认证/权限信息。 
获取当前登入用户：   

```
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
if (principal instanceof UserDetails) {
String username = ((UserDetails)principal).getUsername();
} else {
String username = principal.toString();
}
```
2.`SecurityContext`  
用来存储/获取 `Authentication` 

3.`Authentication`  
代表用户认证信息。  

4.`UserDetails`  
db获取的用户信息，用来构建 `Authentication`  

5.`UserDetailsService`  
唯一的方法: 根据用户名获取用户  

```
UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
```
  
用来获取`UserDetails`，这个对象可看成 对系统的用户实体的包装，获取后，进行用户登录认证，认证成功，用它来
构建 `Authentication` 存储在`SecurityContextHolder`中。   
 
获取的`UserDetails`一般可以直接转换成我们自定义的用户实体，从而使用系统用户实体上定义的方法。  

`UserDetailsService`可以自定义，进而从database加载用户信息。该用户信息可以直接从1.`SecurityContextHolder`中获取。  

6.`GrantedAuthority`  

用户权限实体，授予用户的权限。  认证成功后可通过 `Authentication.getAuthorities()`获取。  


** Authentication**  
认证：What is authentication in Spring Security?  

1，用户访问带系统登入页面，被提示输入用户和密码进行认证；  
2，系统校验用户填写的账号信息；
3，系统保存用户的认证信息和权限信息到上下文；  
4，系统基于用户信息构建`SecurityContext`存储于session，每次请求利用`SecurityContextHolder`存到`ThreadLocal`中，请求完毕再从`SecurityContextHolder`中删除。  `SecurityContext`保存了认证信息`Authentication`；  
5，经过1-4用户认证成功，用户访问权限保护的资源，再进行权限的校验。  

认证的细节：  
用户提交的用户名密码并存储在`UsernamePasswordAuthenticationToken`中，token实体传给  
`AuthenticationManager`进行校验，`AuthenticationManager`校验成功，返回一个填充了用户详情(`UserDetails`)和权限
信息 的(`GrantedAuthority`)`Authentication`。  
最后调用`SecurityContextHolder.getContext().setAuthentication(…)`建立`SecurityContext`并把`Authentication`
存储起来。  

认证流程大致代码如下：  

```
private static AuthenticationManager am = new SampleAuthenticationManager();

while(true) {
	System.out.println("Please enter your username:");
	String name = in.readLine();
	System.out.println("Please enter your password:");
	String password = in.readLine();
	try {
		Authentication request = new UsernamePasswordAuthenticationToken(name, password);
		Authentication result = am.authenticate(request);
		SecurityContextHolder.getContext().setAuthentication(result);
		break;
	} catch(AuthenticationException e) {
		System.out.println("Authentication failed: " + e.getMessage());
	}
 }
	System.out.println("Successfully authenticated. Security context contains: " +
	SecurityContextHolder.getContext().getAuthentication());
	
//简单的认证管理器
class SampleAuthenticationManager implements AuthenticationManager {
 	static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();
	static {
	AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
	}
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		if (auth.getName().equals(auth.getCredentials())) {
		return new UsernamePasswordAuthenticationToken(auth.getName(),
		auth.getCredentials(), AUTHORITIES);
	}
	throw new BadCredentialsException("Bad Credentials");
	}
}
```

** Authentication in a Web Application**  

*How is a user authenticated and the security context established?*  
1. You visit the home page, and click on a link.  
2. A request goes to the server, and the server decides that you’ve asked for a protected resource.  
3. As you’re not presently authenticated, the server sends back a response indicating that you must
authenticate. The response will either be an HTTP response code, or a redirect to a particular web
page.  
4. Depending on the authentication mechanism, your browser will either redirect to the specific web
page so that you can fill out the form, or the browser will somehow retrieve your identity (via a BASIC
authentication dialogue box, a cookie, a X.509 certificate etc.).  
5. The browser will send back a response to the server. This will either be an HTTP POST containing
the contents of the form that you filled out, or an HTTP header containing your authentication details.  
6. Next the server will decide whether or not the presented credentials are valid. If they’re valid, the
next step will happen. If they’re invalid, usually your browser will be asked to try again (so you return
to step two above).  
7. The original request that you made to cause the authentication process will be retried. Hopefully
you’ve authenticated with sufficient granted authorities to access the protected resource. If you have
sufficient access, the request will be successful. Otherwise, you’ll receive back an HTTP error code
403, which means "forbidden".  


*Authentication Mechanism*  

认证机制：  
1.收集用户提交的认证凭证(credentials)；    
2.利用用户凭证构建请求Authentication对象交给 AuthenticationManager管理器进行认证；  
3.认证成功后，会返回一个被填充了用户凭证和权限信息的Authentication对象，此时请求被认为是合法的，接着把Authentication
放入SecurityContextHolder并重新求请求所访问的资源(重定向到受保护的资源)。否则 拒绝请求并定向到失败页面。  


*Storing the SecurityContext between requests*  
>保存全局的`SecurityContext`  

用户认证一次，并在会话中保存登录的用户信息。  
保存会话级别的`SecurityContext` 实现者：`SecurityContextPersistenceFilter`as SCPF   
默认情况，认证成功后 SCPF 保存 SecurityContext 到HttpSession中，每次请求时，SCPF把`SecurityContext`  
保存到 `SecurityContextHolder`中，同时，请求结束时 从`SecurityContextHolder`中删除`SecurityContext`   
因此应用想获取用户信息，直接使用`SecurityContextHolder`而没必要使用`HttpSession`获取。  

在单个会话中 `SecurityContext`是session共享的，每次请求时，会放入ThreadLocal，请求结束时从ThreadLocal中删除。  
因涉及到ThreadLocal，所以 `SecurityContext`对象也是多线程共享的对象。所以不要调用：  
`SecurityContextHolder.getContext().setAuthentication(anAuthentication)`去修改保存在
共享变量`SecurityContext`中的anAuthentication，否则会影响其他线程对该变量的使用。  

** Access-Control (Authorization) in Spring Security**  
> 访问受保护资源时需要授权。此过程是在认证成功后访问收保护的资源时进行的。  

决定资源是否有权访问的类：`AccessDecisionManager`

具备的方法：  

```
void decide(Authentication authentication, Object object,
			Collection<ConfigAttribute> configAttributes) throws AccessDeniedException,
			InsufficientAuthenticationException;
```
参数说明：  
authentication： 认证成功时填充了用户信息和权限的对象  
object: 收到保护的对象    
configAttributes： 配置到 object 对象关联的权限集或属性集     

*Security and AOP Advice*  

AspectJ or Spring AOP 的环绕通知实现受保护的方法调用method invocations鉴权；  
Filters 实现 web请求鉴权(web request authorization).  

三种方式可以混合使用：  
`most Spring applications will simply use the three currently supported secure object types` 
`AOP Alliance MethodInvocation, AspectJ JoinPoint and web request FilterInvocation`

*Secure Objects and the AbstractSecurityInterceptor*  

So what is a "secure object" anyway?  
应用(配置)了安全相关的权限的对象。常用的例子就是：方法调用和受保护的资源请求。  

每种受保护对象类型都对应一个拦截器，拦截器的通用父类：`AbstractSecurityInterceptor`  

访问受保护资源对象时`AbstractSecurityInterceptor`的工作流程：  
1. Look up the "configuration attributes" associated with the present request  
2. Submitting the secure object, current Authentication and configuration attributes to the
AccessDecisionManager for an authorization decision  
3. Optionally change the Authentication under which the invocation takes place  
4. Allow the secure object invocation to proceed (assuming access was granted)  
5. Call the AfterInvocationManager if configured, once the invocation has returned. If the
invocation raised an exception, the AfterInvocationManager will not be invoked.  

*What are Configuration Attributes?*  
可以认为是配置到受保护对象上的注解属性集，一般是权限名字的集合。  

SecurityMetadataSource对象用来获取受保护对象上的注解属性并封装成ConfigAttribute对象。  


*AfterInvocationManager* 
> 鉴权成功后，方法调用完毕后对返回值的最后修改。


** Core Services**  

>更近一步的核心接口实现类 配置和操作。  

*The AuthenticationManager, ProviderManager and AuthenticationProvider*  

`AuthenticationManager`默认实现：`ProviderManager`  

他不处理请求认证，而是代理了一系列`AuthenticationProvider`去做请求认证，`AuthenticationProvider`  
要么抛出异常要么返回一个已经认证成功的且被填充了用户凭证和权限的`Authentication`对象，代表认证成功。  

该对象通常被注入到一些filter中，用来处理认证请求。  

* Erasing Credentials on Successful Authentication  

>认证成功后擦除用户认证的敏感信息，比如密码。  


* DaoAuthenticationProvider    

> The  simplest  AuthenticationProvider  implemented  by  Spring  Security 

*UserDetailsService Implementations*  

* In-Memory Authentication  

>内存级别 用户信息  

* JdbcDaoImpl  

>obtain user information from JDBC data source, Spring JDBC is used

如果使用其他的ORM映射工具 比如mybatis,那么需要自定义UserDetailsService实现类来获取用户信息。  

```
<bean id="userDetailsService"
	class="org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl">
	<property name="dataSource" ref="dataSource"/>
</bean>
```

* Authority Groups  

>权限组 
默认是简单的权限，如果想做更加灵活的分组 则需要自定义实现。  

#### Authentication  

>1.In-Memory Authentication  
>2.JDBC Authentication  
>LDAP Authentication 

 