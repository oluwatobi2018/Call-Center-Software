<?php

namespace CallCenter\Component\Encrypter;

use gnupg;
use Exception;

/**
 * Class to encrypt and decrypt data using gnupg.
 *
 * The intended use of this class is to encrypt data that will be decrypted with a passphrase provided by a user trough a form
 * in a webpage, therefore, GnuPG v 1.0 SHOULD be used in order to send the passphrase as plain text trough HTTP.
 * Version 2 of GnuPG DOESN'T allow to send plain text passprahse trough HTTP.
 *
 * A valid key pair MUST exists in the server, otherwise this class will throw an exception. See the docs in Confluence.
 *
 * @see http://php.net/manual/en/book.gnupg.php
 * @see https://www.gnupg.org/gph/en/manual/c14.html#AEN25
 */
class GnuPG
{
    /**
     * @var string
     */
    protected $recipient = '';

    /**
     * @var string
     */
    protected $passphrase = '';

    /**
     * @var string
     */
    protected $gnupghome = '';

    /**
     * @var object
     */
    protected $gnupg;

    /**
     * @var object
     */
    protected $logger;

    /**
     * Class constructor.
     *
     * @param string $recipient
     * @param string $passphrase
     * @param string $gnupghome
     * @param object $logger
     */
    public function __construct($recipient, $passphrase, $gnupghome, $logger)
    {
        $this->recipient = $recipient;
        $this->passphrase = $passphrase;
        $this->gnupghome = $gnupghome;
        $this->logger = $logger;

        $this->setGnuPGEnvVariable();
        $this->gnupg = new gnupg();
        $this->setGnuPGErrorMode();
    }

    /**
     * Encrypt data.
     *
     * @param string $data
     *
     * @throws Exception
     *
     * @return string
     */
    public function encrypt($data)
    {
        try {
            $this->gnupg->addencryptkey($this->recipient);
            if (!empty($this->passphrase)) {
                $this->gnupg->addsignkey($this->getFingerprint(), $this->passphrase);
                $chiperdata = $this->gnupg->encryptsign($data);
            } else {
                $chiperdata = $this->gnupg->encrypt($data);
            }

            return $chiperdata;
        } catch (Exception $e) {
            $this->logger->error($e->getMessage());
        }
    }

    /**
     * Decrypt data.
     *
     * @param string $data
     *
     * @throws Exception
     *
     * @return string
     */
    public function decrypt($data)
    {
        try {
            $this->gnupg->adddecryptkey($this->recipient, $this->passphrase);

            return $this->gnupg->decrypt($data);
        } catch (Exception $e) {
            $this->logger->error($e->getMessage());
        }
    }

    /**
     * Setup the GnuPG path environment variable.
     */
    private function setGnuPGEnvVariable()
    {
        putenv('GNUPGHOME='.$this->gnupghome);
    }

    /**
     * Return the fingerprint of the keyring to encrypt data.
     *
     * @todo add ckeck on fingerprint against recipient, in case of posible multiple keys in the server
     *
     * @throws Exception
     *
     * @return string
     */
    private function getFingerprint()
    {
        try {
            $fingerprint = '';
            $records = $this->gnupg->keyinfo('');
            foreach ($records as $record) {
                foreach ($record['subkeys'] as $subkey) {
                    if ($subkey['can_encrypt'] == 1) {
                        //TODO: check if email and recipient match before asign $fingerprint variable
                        $fingerprint = $subkey['fingerprint'];
                    }
                }
            }

            return $fingerprint;
        } catch (Exception $e) {
            $this->logger->error($e->getMessage());
        }
    }

    /**
     * Set the gnupg extension eror mode to throw an Exception in case of failure.
     */
    private function setGnuPGErrorMode()
    {
        $this->gnupg->seterrormode(gnupg::ERROR_EXCEPTION);

    }
}
<?php

namespace CallCenter\Bundle\CommonBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="homepage")
     */
    public function indexAction(Request $request)
    {
        // replace this example code with whatever you need
        return $this->render('default/index.html.twig', [
            'base_dir' => realpath($this->getParameter('kernel.root_dir').'/..').DIRECTORY_SEPARATOR,
        ]);
    }
}
<?php

namespace CallCenter\Bundle\CommonBundle\DBAL\Types;

use Fresh\DoctrineEnumBundle\DBAL\Types\AbstractEnumType;

final class BankAccountType extends AbstractEnumType
{
    const CAJA_AHORRO = 'CA';
    const CUENTA_CORRIENTE = 'CC';
    const JUDICIALES = 'J';

    protected static $choices = [
        self::CAJA_AHORRO => 'Caja de Ahorro',
        self::CUENTA_CORRIENTE => 'Cuenta Corriente',
        self::JUDICIALES => 'Judiciales',
    ];
}
namespace CallCenter\Bundle\CommonBundle\DBAL\Types;

use Fresh\DoctrineEnumBundle\DBAL\Types\AbstractEnumType;

final class GenderType extends AbstractEnumType
{
    const MALE = 'F';
    const FEMALE = 'M';

    protected static $choices = [
        self::MALE => 'Male',
        self::FEMALE => 'Female',
    ];
}
namespace CallCenter\Bundle\CommonBundle\DBAL\Types;

use Fresh\DoctrineEnumBundle\DBAL\Types\AbstractEnumType;

final class IdentityDocumentType extends AbstractEnumType
{
    const DNI = 'DNI';
    const LE = 'LE';
    const LC = 'LC';

    protected static $choices = [
        self::DNI => 'Documento Nacional de Identidad',
        self::LE => 'Libreta de Enrolamiento',
        self::LC => 'Licencia de Conducir',
    ];
}
namespace CallCenter\Bundle\CommonBundle\DependencyInjection;

use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;

class CommonExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader(
            $container,
            new FileLocator(__DIR__.'/../Resources/config')
        );
        $loader->load('services.yml');

        $configuration = $this->getConfiguration($configs, $container);
        $config = $this->processConfiguration($configuration, $configs);

        // Fill the array with classes when appropiate
        $this->addClassesToCompile(array());
    }

    /**
     * {@inheritdoc}
     */
    public function getConfiguration(array $config, ContainerBuilder $container)
    {
        return new Configuration($container->getParameter('kernel.debug'));
    }
}
namespace CallCenter\Bundle\CommonBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    private $debug;

    /**
     * @param bool $debug Whether debugging is enabled or not
     */
    public function __construct($debug)
    {
        $this->debug = (bool) $debug;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('call_center_platform');

        $rootNode
            ->children()
                ->arrayNode('twitter')
                    ->children()
                        ->integerNode('client_id')->end()
                        ->scalarNode('client_secret')->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
namespace CallCenter\Bundle\CommonBundle\Entity\Embeddable;

use Symfony\Component\Validator\Constraints as Assert;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Embeddable
 */
class AddressEmbeddable
{
    /**
     * @ORM\Column(
     *      name="street",
     *      type="string"
     * )
     * @Assert\NotBlank()
     */
    private $street;

    /**
     * @ORM\Column(
     *      name="postal_code",
     *      type="string"
     * )
     */
    private $postalCode;

    /**
      * @ORM\Column(
     *      name="city",
     *      type="string"
     * )
     * @Assert\NotBlank()
     */
    private $city;

    /**
     * @ORM\Column(
     *      name="country"
     *      type="string"
     * )
     * @Assert\NotBlank()
     */
    private $country;
}
namespace CallCenter\Bundle\CommonBundle\Entity\Embeddable;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Embeddable
 */
class CurrencyEmbeddable
{
}
namespace CallCenter\Bundle\CommonBundle\Entity\Embeddable;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Embeddable
 */
class GenderEmbeddable
{
}
namespace CallCenter\Bundle\CommonBundle\Entity\Embeddable;

use Symfony\Component\Validator\Constraints as Assert;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Embeddable
 */
class PhoneEmbeddable
{
    /*
     * @ORM\Column(
     *      name="number",
     *      type="integer"
     * )
     * @Assert\NotBlank()
     */
    private $number;

    /*
     * @ORM\Column(
     *      name="description",
     *      type="string"
     * )
     */
    private $description;
}