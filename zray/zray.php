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

	public function setZRE($zre) {
		$this->zre = $zre;
	}


	public function eventDispatchExit($context, &$storage) {

		// The arguments order of EventDispatcher::dispatch() method has changed with that commit:
		// https://github.com/symfony/symfony/commit/75369dabb8af73b0d0ad7f206d85c08cf39117f8#diff-85cb8e51b93fa5b47bf21ced693087e38c7331684d8c4188724127d6c85da74d
		// In order to support Symfony versions before and after that change, we check if the first
		// argument is an object. If yes, then we can get the event object from first argument and name
		// from the second (newer version of Symfony). And if not, we assume that the name string is first
		// argument and event object second argument.
		if (is_object($context['functionArgs'][0])) {
			$event = $context['functionArgs'][0];
			$name = $context['functionArgs'][1];
		} else {
			$event = $context['functionArgs'][1];
			$name = $context['functionArgs'][0];
		}

		if (empty($event)) {
			return;
		}

		//Laravel 3 fixes
		if(!method_exists ( $event ,'getName' ) ){
			$name = (!empty($name)) ? $name : 'N/A';
		} else {
			$name = $event->getName();
		}

		if(!method_exists ( $event ,'getDispatcher' ) ){
			$dispatcher = 'N/A';
		}else{
			$dispatcher = $event->getDispatcher();
		}

		$storage['events'][] = array(
						'name' => $name,
						'type' => get_class($event),
						'dispatcher' => $dispatcher,
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
		try {
		$securityCtx = $thisCtx->getContainer()->get('security.context');
		}catch(\Exception $e){
		$securityCtxToken = $thisCtx->getContainer()->get('security.token_storage');
		$securityCtxGrunt = $thisCtx->getContainer()->get('security.authorization_checker');
		}
		$securityToken = (isset($securityCtxToken) ? $securityCtxToken->getToken() : null);

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
			if ($isAuthenticated) {
				if ($securityCtxGrunt->isGranted('IS_AUTHENTICATED_FULLY')) {
					$authType = 'IS_AUTHENTICATED_FULLY';
				} else if ($securityCtxGrunt->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
					$authType = 'IS_AUTHENTICATED_REMEMBERED';
				} else if ($securityCtxGrunt->isGranted('IS_AUTHENTICATED_ANONYMOUSLY')) {
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

		$record = $context['locals']['record'];


		$storage['Monolog'][] = array(
						'#' => ++$logCount,
						'message' => $record['message'],
						'level' => $record['level_name'],
						'channel' => $record['channel'],
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


