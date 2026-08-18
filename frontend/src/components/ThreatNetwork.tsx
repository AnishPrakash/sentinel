import { Canvas, useFrame } from "@react-three/fiber";
import { Line, PerspectiveCamera } from "@react-three/drei";
import { useRef } from "react";
import * as THREE from "three";

const nodes = [
  [-2.4, 1.5, 0],
  [2.3, 1.2, -0.5],
  [-2.1, -1.4, 0.4],
  [2.2, -1.3, 0],
  [0, 0, 0],
] as [number, number, number][];

const connections = [
  [0, 4],
  [1, 4],
  [2, 4],
  [3, 4],
  [0, 1],
  [2, 3],
];

function NetworkNode({
  position,
  core = false,
  threat = false,
}: {
  position: [number, number, number];
  core?: boolean;
  threat?: boolean;
}) {
  const meshRef = useRef<THREE.Mesh>(null);

  const offset =
    position[0] * 2 +
    position[1] * 3;

  useFrame((state) => {
    if (!meshRef.current) return;

    const time = state.clock.elapsedTime;

    const pulse = Math.sin(
      time *
        (threat
          ? 3.2
          : core
          ? 2.2
          : 1.5) +
        offset
    );

    const scale = threat
      ? 1 + pulse * 0.18
      : core
      ? 1 + pulse * 0.08
      : 1 + pulse * 0.12;

    meshRef.current.scale.setScalar(scale);

    meshRef.current.position.y =
      position[1] +
      Math.sin(time * 0.7 + offset) * 0.04;
  });

  const nodeColor = threat
    ? "#ef4444"
    : core
    ? "#d8b4fe"
    : "#818cf8";

  const emissiveColor = threat
    ? "#dc2626"
    : core
    ? "#7c3aed"
    : "#4f46e5";

  return (
    <mesh
      ref={meshRef}
      position={position}
    >
        {threat && (
  <mesh rotation={[Math.PI / 2, 0, 0]}>
    <ringGeometry args={[0.18, 0.21, 32]} />

    <meshBasicMaterial
      color="#ef4444"
      transparent
      opacity={0.5}
      toneMapped={false}
    />
  </mesh>
)}
      <sphereGeometry
        args={[
          core ? 0.22 : threat ? 0.13 : 0.1,
          32,
          32,
        ]}
      />

      <meshStandardMaterial
        color={nodeColor}
        emissive={emissiveColor}
        emissiveIntensity={
          threat
            ? 5
            : core
            ? 4
            : 2.5
        }
        roughness={0.25}
        metalness={0.2}
      />

      <pointLight
        color={
          threat
            ? "#ef4444"
            : core
            ? "#8b5cf6"
            : "#6366f1"
        }
        intensity={
          threat
            ? 2
            : core
            ? 2.5
            : 0.7
        }
        distance={
          threat
            ? 2
            : core
            ? 3
            : 1.5
        }
      />
    </mesh>
  );
}

function DataPacket({
  start,
  end,
  delay = 0,
  color = "#22d3ee",
}: {
  start: [number, number, number];
  end: [number, number, number];
  delay?: number;
  color?: string;
}) {
  const packetRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (!packetRef.current) return;

    const time = state.clock.elapsedTime;

    const duration = 3;

    const progress =
      ((time + delay) % duration) / duration;

    const smoothProgress =
      progress < 0.5
        ? progress * 2
        : 2 - progress * 2;

    packetRef.current.position.lerpVectors(
      new THREE.Vector3(...start),
      new THREE.Vector3(...end),
      smoothProgress
    );
  });

  return (
    <mesh ref={packetRef}>
      <sphereGeometry args={[0.045, 16, 16]} />

      <meshBasicMaterial
        color={color}
        toneMapped={false}
      />

      <pointLight
        color={color}
        intensity={1.5}
        distance={0.8}
      />
    </mesh>
  );
}

function ThreatPacket({
  active = true,
}: {
  active?: boolean;
}) {
  if (!active) {
    return null;
  }

  const packetRef = useRef<THREE.Mesh>(null);

  const path = [
    new THREE.Vector3(-2.4, 1.5, 0),
    new THREE.Vector3(0, 0, 0),
    new THREE.Vector3(2.3, 1.2, -0.5),
  ];

  useFrame((state) => {
    if (!packetRef.current) return;

    const time = state.clock.elapsedTime;

    const duration = 5;

    const progress =
      (time % duration) / duration;

    let position: THREE.Vector3;

    if (progress < 0.5) {
      const localProgress = progress * 2;

      position = new THREE.Vector3().lerpVectors(
        path[0],
        path[1],
        localProgress
      );
    } else {
      const localProgress = (progress - 0.5) * 2;

      position = new THREE.Vector3().lerpVectors(
        path[1],
        path[2],
        localProgress
      );
    }

    packetRef.current.position.copy(position);
  });

  return (
    <mesh ref={packetRef}>
      <sphereGeometry args={[0.075, 20, 20]} />

      <meshBasicMaterial
        color="#ef4444"
        toneMapped={false}
      />

      <pointLight
        color="#ef4444"
        intensity={3}
        distance={1.5}
      />
    </mesh>
  );
}

function Network({
  threatMode = false,
}: {
  threatMode?: boolean;
}) {
    const compromisedNodes = new Set(
  threatMode ? [0, 4, 1] : []
);
  const groupRef = useRef<THREE.Group>(null);

  useFrame((state) => {
    if (!groupRef.current) return;

    const time = state.clock.elapsedTime;

    const mouseX = state.pointer.x;
    const mouseY = state.pointer.y;

    const targetRotationY =
      mouseX * 0.18 +
      Math.sin(time * 0.15) * 0.06;

    const targetRotationX =
      -mouseY * 0.12 +
      Math.sin(time * 0.12) * 0.03;

    groupRef.current.rotation.y +=
      (targetRotationY - groupRef.current.rotation.y) * 0.04;

    groupRef.current.rotation.x +=
      (targetRotationX - groupRef.current.rotation.x) * 0.04;

    groupRef.current.position.x = mouseX * 0.12;
    groupRef.current.position.y = mouseY * 0.08;
  });

  return (
    <group ref={groupRef}>
      {connections.map(([from, to], index) => {
        const start = nodes[from];
        const end = nodes[to];

        const isThreatConnection =
  threatMode &&
  (
    (from === 0 && to === 4) ||
    (from === 4 && to === 1) ||
    (from === 1 && to === 4)
  );

return (
  <Line
    key={index}
    points={[start, end]}
    color={
      isThreatConnection
        ? "#ef4444"
        : "#6366f1"
    }
    transparent
    opacity={
      isThreatConnection
        ? 0.8
        : 0.35
    }
    lineWidth={
      isThreatConnection
        ? 1.8
        : 1
    }
  />
);
      })}

      {connections.map(([from, to], index) => (
        <DataPacket
            key={`packet-${index}`}
            start={nodes[from]}
            end={nodes[to]}
            delay={index * 0.7}
        />
        ))}

        <ThreatPacket active={threatMode} />

      {nodes.map((position, index) => (
        <NetworkNode
            key={index}
            position={position}
            core={index === 4}
            threat={compromisedNodes.has(index)}
        />
        ))}
    </group>
  );
}

function FloatingParticles() {
  const particlesRef = useRef<THREE.Points>(null);

  useFrame((state) => {
    if (!particlesRef.current) return;

    const time = state.clock.elapsedTime;

    particlesRef.current.rotation.y =
      time * 0.025;

    particlesRef.current.rotation.x =
      Math.sin(time * 0.1) * 0.04;
  });

  return (
    <points ref={particlesRef}>
      <sphereGeometry args={[3.8, 32, 32]} />

      <pointsMaterial
        color="#6366f1"
        size={0.025}
        transparent
        opacity={0.45}
        sizeAttenuation
      />
    </points>
  );
}

function CameraController() {
  const cameraRef =
    useRef<THREE.PerspectiveCamera>(null);

  useFrame((state) => {
    if (!cameraRef.current) return;

    const mouseX = state.pointer.x;
    const mouseY = state.pointer.y;

    cameraRef.current.position.x +=
      (mouseX * 0.25 -
        cameraRef.current.position.x) *
      0.03;

    cameraRef.current.position.y +=
      (-mouseY * 0.15 -
        cameraRef.current.position.y) *
      0.03;

    cameraRef.current.lookAt(0, 0, 0);
  });

  return (
    <PerspectiveCamera
      ref={cameraRef}
      makeDefault
      position={[0, 0, 7]}
      fov={45}
    />
  );
}

function ThreatNetwork({
  threatMode = false,
}: {
  threatMode?: boolean;
}) {
  return (
    <div className="threat-network-3d">
      <Canvas>
        <CameraController />

        <ambientLight intensity={0.25} />

        <pointLight
          position={[0, 0, 3]}
          intensity={2}
          color="#7c3aed"
        />

        <pointLight
          position={[-3, 2, 2]}
          intensity={1}
          color="#2563eb"
        />

        <Network threatMode={threatMode} />

        <FloatingParticles />
      </Canvas>
    </div>
  );
}

export default ThreatNetwork;