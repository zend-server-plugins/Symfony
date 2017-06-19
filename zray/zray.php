<?php
/*********************************
	Symfony Z-Ray Extension
**********************************/
namespace ZRay;

class Symfony {
	/**
	 * @var \Symfony\Component\HttpKernel\Kernel
	 */
	private $kernel;
	private $tracedAlready = false;
	private $zre = null;

	const NULL_ON_INVALID_REFERENCE = 2;

	public function setZRE($zre) {
		$this->zre = $zre;
	}


	public function eventDispatchExit($context, &$storage) {
		if(!$context['functionArgs'][1]) { return; }
		$eventname = $context['functionArgs'][0];
		$event = $context['functionArgs'][1];
		$storage['events'][] = array(	
						'name' => $eventname,
						'type' => get_class($event),
						'dispatcher' => get_class($context['this']),
						'propagation stopped' => $event->isPropagationStopped(),
						);
	}

	public function registerBundlesExit($context, &$storage) {
		$bundles = $context['returnValue'];

		foreach ($bundles as $bundle) {
			$storage['bundles'][] = @array(
							'name' => $bundle->getName(),
							'namespace' => $bundle->getNamespace(),
							'container' => get_class($bundle->getContainerExtension()),
							'path' => $bundle->getPath(),
						);
		}
	}

	public function handleRequestExit($context, &$storage) {
		$request = $context['functionArgs'][0];
		
		if (empty($request)) {
			return;
		}
		$ctrl = $request->get('_controller');
		if (empty($ctrl)) {
			return;
		}
		if (empty($ctrl) || !(is_array($ctrl) || is_string($ctrl))) {
		   return;
		} elseif (is_string($ctrl)) {
		   $ctrl = explode(':', $ctrl);
		}
		$controller = $ctrl[0];
		if (!empty($ctrl[2])) {
			$action = $ctrl[2];
		} else {
			$action = $ctrl[1];
		}
		try {
			$refclass = new \ReflectionClass($controller);
			$filename = $refclass->getFileName();
			$lineno = $refclass->getStartLine();
		} catch (\Exception $e) {
			$filename = $lineno = '';
		}
		$storage['request'][] = @array(
						'Controller' => $controller,
						'Action' => $action,
						'Filename' => $filename,
						'Line Number' => $lineno,
						'Route' => array(	
							'Name' => $request->get('_route'),
							'Params' => $request->get('_routeparams'),
							),
						'Session' => ($request->getSession() ? 'yes' : 'no'),
						'Locale' => $request->getLocale(),
					);
	}

	public function terminateExit($context, &$storage){
		$thisCtx = $context['this'];

		$listeners = $thisCtx->getContainer()->get('event_dispatcher')->getListeners();

		foreach ($listeners as $listenerName => $listener) {

			$listenerEntry = array();
			$handlerEntries = array();
			foreach ($listener as $callable) {
				switch(gettype($callable)) {
					case 'array':
						if (gettype($callable[0])=='string') {
							$strCallable = $callable[0].'::'.$callable[1];
						} else {
							$strCallable = get_class($callable[0]).'::'.$callable[1];
						}
						break;
					case 'string':
						$strCallable = $callable;
						break;
					case 'object':
						$strCallable = get_class($callable);
						break;
					default:
						$strCallable = 'unknown';
						break;
				}
				$listenerEntries[$listenerName][] = $strCallable;
			}
		}
		$storage['listeners'][] = $listenerEntries;

		$container = $thisCtx->getContainer();
		// Older versions of Symfony used security.context.  This was changed to security.token_storage in 2.6.
		$securityCtx = $thisCtx->getContainer()->get('security.context', self::NULL_ON_INVALID_REFERENCE);
		if ($securityCtx) {
			$securityCkr = $securityCtx; // Symfony has a single context for the token and the authorization checker
		} else {
			$securityCtx = $thisCtx->getContainer()->get('security.token_storage', self::NULL_ON_INVALID_REFERENCE);
			$securityCkr = $thisCtx->getContainer()->get('securoty.authorization_checker', self::NULL_ON_INVALID_REFERENCE);
		}
		$securityToken = ($securityCtx ? $securityCtx->getToken() : null);
		$isAuthenticated = false;
		$authType = '';
		$attributes = array();
		$userId = '';
		$username = '';
		$salt = '';
		$password = '';
		$email = '';
		$isEnabled = '';
		$roles = array();
		$tokenClass = 'No security token available';

		if ($securityToken) {
			$attributes = $securityToken->getAttributes();
			$tokenClass = get_class($securityToken);
			
			$isAuthenticated = $securityToken->isAuthenticated();
			if ($securityCkr && $isAuthenticated) {
				if ($securityCkr->isGranted('IS_AUTHENTICATED_FULLY')) {
					$authType = 'IS_AUTHENTICATED_FULLY';
				} else if ($securityCkr->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
					$authType = 'IS_AUTHENTICATED_REMEMBERED';
				} else if ($securityCkr->isGranted('IS_AUTHENTICATED_ANONYMOUSLY')) {
					$authType = 'IS_AUTHENTICATED_ANONYMOUSLY';
				} else {
					$authType = 'Unknown';
				}
			}
			$user = $securityToken->getUser();
			if ($user) {
				if ($user !== 'anon.') {
					$userId    = (method_exists($user,'getId'))        ? $user->getId()        : '';
					$username  = (method_exists($user,'getUsername'))  ? $user->getUsername()  : '';
					$salt      = (method_exists($user,'getSalt'))      ? $user->getSalt()      : '';
					$password  = (method_exists($user,'getPassword'))  ? $user->getPassword()  : '';
					$email     = (method_exists($user,'getEmail'))     ? $user->getEmail()     : '';
					$isEnabled = (method_exists($user,'isEnabled'))    ? $user->isEnabled()    : '';
					$roles     = (method_exists($user,'getRoles'))     ? $user->getRoles()     : '';
				} else {
					$username = 'anonymous';
				}
			}
		}

		$storage['security'][] = @array(
						'isAuthenticated' => $isAuthenticated,
						'username' => $username,
						'user id' => $userId,
						'roles' => $roles,
						'authType' => $authType,
						'isEnabled' => $isEnabled,
						'email' => $email,
						'attributes' => $attributes,
						'password' => $password,
						'salt' => $salt,
						'token type' => $tokenClass,
						);

	}
	
	public function logAddRecordExit($context, &$storage) {
		static $logCount = 0;
		$levelnames = array (
			100 => 'Debug', 200 => 'Info', 250 => 'Notice', 300 => 'Warning', 400 => 'Error',
			500 => 'Critical', 550 => 'Alert', 600 => 'Emergency'
		);

		$level = $context['functionArgs'][0];
		$message = $context['functionArgs'][1];

		$storage['Monolog'][] = array(
						'#' => ++$logCount,
						'message' => $message,
						'level' => isset ($levelnames[$level]) ? $levelnames[$level] : $level,
						'channel' => $context['this']->getName(),
					);
	}
}

$zre = new \ZRayExtension("symfony");

$zraySymfony = new Symfony();
$zraySymfony->setZRE($zre);

$zre->setMetadata(array(
	'logo' => __DIR__ . DIRECTORY_SEPARATOR . 'logo.png',
));

$zre->setEnabledAfter('Symfony\Component\HttpFoundation\Request::initialize');

$zre->traceFunction("Symfony\Component\HttpKernel\Kernel::terminate", function(){}, array($zraySymfony, 'terminateExit'));
$zre->traceFunction("Symfony\Component\HttpKernel\HttpKernel::handle", function(){}, array($zraySymfony, 'handleRequestExit'));
$zre->traceFunction("Symfony\Component\EventDispatcher\EventDispatcher::dispatch", function(){}, array($zraySymfony, 'eventDispatchExit'));
$zre->traceFunction("AppKernel::registerBundles", function(){}, array($zraySymfony, 'registerBundlesExit'));
$zre->traceFunction("Monolog\Logger::addRecord", function(){}, array($zraySymfony, 'logAddRecordExit'));
